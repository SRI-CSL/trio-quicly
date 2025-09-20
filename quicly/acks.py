#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from dataclasses import dataclass, field
from typing import *

from .frame import QuicFrameType, ACKFrame, ACKRange, QuicFrame, FrameSubtype
from .utils import K_MICRO_SECOND, K_GRANULARITY

Interval = Tuple[int, int]  # [low, high], inclusive

def iter_ack_frames(frames: Iterable[object]) -> Iterator[ACKFrame]:
    """
    Yield ACK/ACK_ECN frames from a list of decoded frames (either wrapper QuicFrame or raw ACKFrame).
    """
    for f in frames:
        # raw ACKFrame support
        if isinstance(f, ACKFrame):
            yield f
            continue

        # wrapper support
        ft = getattr(f, "frame_type", None)
        content = getattr(f, "content", None)
        if ft in (QuicFrameType.ACK, QuicFrameType.ACK_ECN) and isinstance(content, ACKFrame):
            yield content

def ack_to_intervals(ack: FrameSubtype) -> List[Interval]:
    """
    Expand ACKFrame’s compact ranges into a descending list of [low, high] intervals.
    """
    if not isinstance(ack, ACKFrame):
        return []

    largest_ack = ack.largest_ack
    low = largest_ack - ack.first_ack_range
    high = largest_ack
    out: List[Interval] = [(low, high)]

    prev_low = low
    for r in ack.ack_ranges:
        next_high = prev_low - r.gap - 2  # ← spec-correct
        next_low  = next_high - r.ack_range_length
        if next_low < 0 or next_low > next_high:
            raise ValueError("ACK range underflow/inversion")
        out.append((next_low, next_high))
        prev_low = next_low
    return out

@dataclass
class SentPacket:
    pn: int
    time_sent: float
    size: int
    ack_eliciting: bool
    in_flight: bool
    is_initial: bool
    frames: list[QuicFrame] = field(default_factory=list)  # whatever you need to retransmit if lost?

@dataclass
class PacketNumberSpace:
    # prior coed: class QuicPacketSpace:
    # ack_at: Optional[float] = None
    # expected_packet_number: int = 0
    _largest_ack_eliciting_packet: int = -1
    largest_received_packet_number: int = -1
    largest_received_time: Optional[float] = None
    # sent packets and loss
    ack_eliciting_in_flight = 0
    ack_eliciting_bytes_in_flight = 0
    largest_acked_packet = -1
    loss_time: Optional[float] = None
    sent_packets: Dict[int, SentPacket] = field(default_factory=dict)

    # Keep intervals sorted by LOW ascending (best for merging),
    # disjoint and non-adjacent (we merge adjacency)
    _intervals: List[Interval] = field(default_factory=list)

    @property
    def largest_ack_eliciting_pkt(self):
        return self._largest_ack_eliciting_packet

    @largest_ack_eliciting_pkt.setter
    def largest_ack_eliciting_pkt(self, value):
        if value > self._largest_ack_eliciting_packet:
            self._largest_ack_eliciting_packet = value

    def note_received(self, pn: int, now: float) -> None:
        if pn > self.largest_received_packet_number:
            self.largest_received_packet_number = pn
            self.largest_received_time = now

        """Insert PN as [pn..pn], merging adjacent/overlapping intervals."""
        ivs = self._intervals
        new_lo = new_hi = pn

        # find insertion point by LOW (ascending)
        i = 0
        while i < len(ivs) and ivs[i][0] < pn:
            i += 1

        # merge with LEFT neighbor if it touches/overlaps
        if i > 0 and ivs[i-1][1] + 1 >= new_lo:
            new_lo = ivs[i-1][0]
            new_hi = max(new_hi, ivs[i-1][1])
            i -= 1
            ivs.pop(i)

        # merge with RIGHT neighbors while they touch/overlap
        while i < len(ivs) and ivs[i][0] <= new_hi + 1:
            new_lo = min(new_lo, ivs[i][0])
            new_hi = max(new_hi, ivs[i][1])
            ivs.pop(i)

        ivs.insert(i, (new_lo, new_hi))

    def to_ack_frame(self, frame_type: QuicFrameType, now: float, max_ranges: int | None = None) -> QuicFrame | None:
        """
        Build an QuicFrame representing the current intervals.
        :param frame_type: ACK or ACK_ECN
        :param now: current time
        :param max_ranges: if set, cap how many ranges we advertise (descending from largest).
        :return: QuicFrame representing the current intervals or None, if nothing currently to ACK.
        """
        if not self._intervals:
            return None

        # Sort by HIGH descending for ACK encoding
        ivs = sorted(self._intervals, key=lambda r: r[1], reverse=True)
        if max_ranges is not None:
            ivs = ivs[:max_ranges]

        first_low, first_high = ivs[0]
        largest_ack = first_high
        first_ack_range = largest_ack - first_low

        ack_ranges: List[ACKRange] = []
        prev_low = first_low
        for low, high in ivs[1:]:
            gap = prev_low - 2 - high
            ack_range_length = high - low
            if gap < 0 or ack_range_length < 0:
                # shouldn’t happen if we kept non-overlapping intervals
                continue
            ack_ranges.append(ACKRange(gap=gap, ack_range_length=ack_range_length))
            prev_low = low

        ack_delay_us = int(max(now - self.largest_received_time, K_GRANULARITY) / K_MICRO_SECOND)
        ack = ACKFrame(
            largest_ack=largest_ack,
            ack_delay=ack_delay_us,
            first_ack_range=first_ack_range,
            ack_ranges=ack_ranges,
            ecn_counts=None,
        )
        return QuicFrame(frame_type=frame_type, content=ack)

    def drop_acked_up_to(self, pn: int) -> None:
        """
        Drop all packet numbers <= pn from the tracker. Intervals fully <= pn are
        removed; intervals that straddle pn are trimmed to start at pn+1.
        Useful after including them in an ACK and consider them safe to compact locally.
        """
        new = []
        for lo, hi in self._intervals:
            if hi <= pn:
                # entirely at/below cutoff -> drop
                continue
            if lo <= pn < hi:
                # straddles cutoff -> trim left edge to pn+1
                new.append((pn + 1, hi))
            else:
                # entirely above cutoff -> keep as is
                new.append((lo, hi))
        self._intervals = new
