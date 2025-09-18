import math
from typing import *

from .acks import ack_to_intervals, SentPacket, PacketNumberSpace
from .frame import ACKFrame
#from .congestion import cubic, reno  # noqa
#from .congestion.base import K_GRANULARITY, create_congestion_control
from .packet import QuicPacketType
from .utils import K_MICRO_SECOND, K_GRANULARITY

# loss detection TODO: move these into configuration!
K_PACKET_THRESHOLD = 3  # RFC 9002: no smaller than 3
K_TIME_THRESHOLD = 9 / 8
K_INITIAL_RTT     = 0.333    # 333 ms, per RFC 9002


class QuicPacketRecovery:
    """
    Packet loss detection and congestion controller.
    """

    def __init__(
        self,
        # congestion_control_algorithm: str,
        # initial_rtt: float,
        # max_datagram_size: int,
        peer_completed_address_validation: bool,
        space: PacketNumberSpace,
    ) -> None:
        self.max_ack_delay = 0.025  # TODO: from config...
        self.peer_completed_address_validation = peer_completed_address_validation
        self.space = space

        # loss detection
        self.pto_count = 0
        self._rtt_initial = K_INITIAL_RTT
        self._rtt_initialized = False
        self._rtt_latest = 0.0
        self._rtt_min = math.inf
        self._rtt_smoothed = 0.0
        self._rtt_variance = 0.0
        self._time_of_last_sent_ack_eliciting_packet = 0.0

        # TODO: congestion control; for now, we keep some things local
        self._bytes_in_flight: int = 0  # TODO: move to CC later
        # self._cc = create_congestion_control(
        #     congestion_control_algorithm, max_datagram_size=max_datagram_size
        # )
        # self._pacer = QuicPacketPacer(max_datagram_size=max_datagram_size)

    @property
    def bytes_in_flight(self) -> int:
        return self._bytes_in_flight

    # @property
    # def congestion_window(self) -> int:
    #     return self._cc.congestion_window

    def discard_space(self) -> None:
        # TODO: rename to reset_space or something...

        # self._cc.on_packets_expired(
        #     packets=filter(lambda x: x.in_flight, space.sent_packets.values())
        # )
        self.space.sent_packets.clear()

        self.space.ack_eliciting_in_flight = 0
        self.space.ack_eliciting_bytes_in_flight = 0
        self.space.loss_time = None

        # reset PTO count
        self.pto_count = 0

        # if self._quic_logger is not None:
        #     self._log_metrics_updated()

    def get_loss_detection_time(self) -> float | None:
        # loss timer
        loss_space = self._get_loss_space()
        if loss_space is not None:
            return loss_space.loss_time

        # packet timer
        if not self.peer_completed_address_validation or self.space.ack_eliciting_in_flight > 0:
            timeout = self.get_probe_timeout() * (2 ** self.pto_count)
            return self._time_of_last_sent_ack_eliciting_packet + timeout

        return None

    def get_probe_timeout(self) -> float:
        if not self._rtt_initialized:
            return 2 * self._rtt_initial
        return self._rtt_smoothed + max(4 * self._rtt_variance, K_GRANULARITY) + self.max_ack_delay

    def on_ack_received(self, ack: ACKFrame, phase: QuicPacketType, now: float) -> None:
        """
        Update metrics as the result of an ACK being received.
        """
        intervals = ack_to_intervals(ack)  # [(low, high)] descending by high
        if not intervals:
            return

        is_ack_eliciting = False
        largest_acked = intervals[0][1]  # first high is largest
        if largest_acked > self.space.largest_acked_packet:
            self.space.largest_acked_packet = largest_acked

        sent_map = self.space.sent_packets
        if not sent_map:  # Nothing in flight (pure duplicate/late ACK) -> ignore gracefully
            return

        # Collect newly-acked PNs we actually have in-flight
        def is_acked(pn: int) -> bool:
            # intervals are few; linear check is fine
            for lo, hi in intervals:
                if lo <= pn <= hi:
                    return True
            return False

        acked_pns = sorted([pn for pn in list(sent_map.keys()) if is_acked(pn)])
        if not acked_pns:  # No new info; could be a duplicate ACK
            return

        largest_newly_acked = max(acked_pns)
        largest_sent_time = None
        rtt_sample = None

        # Remove from flight & maybe take RTT sample
        for pn in acked_pns:
            sp = sent_map.pop(pn)
            if sp.ack_eliciting:
                is_ack_eliciting = True
                if sp.in_flight:
                    self.space.ack_eliciting_in_flight -= 1
                    self.space.ack_eliciting_bytes_in_flight -= sp.size
            # TODO: self._cc.on_packet_acked(packet=packet, now=now)
            # Use the largest newly-acked, ack-eliciting packet for RTT
            if pn == largest_newly_acked and sp.ack_eliciting:
                largest_sent_time = sp.time_sent

        if largest_acked == largest_newly_acked and is_ack_eliciting:
            latest_rtt = max(now - largest_sent_time, K_GRANULARITY)

            # limit ACK delay (in ms) to max_ack_delay (in s)
            ack_delay = min(ack.ack_delay * K_MICRO_SECOND, self.max_ack_delay)  # cannot be < 1 ms

            # update RTT estimate:
            if self._rtt_latest < self._rtt_min:
                self._rtt_min = self._rtt_latest
            if self._rtt_latest > self._rtt_min + ack_delay:
                self._rtt_latest -= ack_delay

            if not self._rtt_initialized:
                self._rtt_initialized = True
                self._rtt_variance = latest_rtt / 2
                self._rtt_smoothed = latest_rtt
            else:
                self._rtt_variance = 3 / 4 * self._rtt_variance + 1 / 4 * abs(
                    self._rtt_min - self._rtt_latest
                )
                self._rtt_smoothed = (
                    7 / 8 * self._rtt_smoothed + 1 / 8 * self._rtt_latest
                )
            # TODO: inform congestion controller
            # self._cc.on_rtt_measurement(now=now, rtt=latest_rtt)
            # self._pacer.update_rate(
            #     congestion_window=self._cc.congestion_window,
            #     smoothed_rtt=self._rtt_smoothed,
            # )

        # are there any prior packets in-flight but not acknowledged and
        # (> K_PACKET_THRESHOLD or time_sent > time threshold)?
        self._detect_loss(now=now)

        # reset PTO count (unless in INITIAL phase at client, note: INITIAL packet at server should not contain ACKs)
        if phase != QuicPacketType.INITIAL:
            self.pto_count = 0

    def on_loss_detection_timeout(self, *, now: float) -> None:
        loss_space = self._get_loss_space()
        if loss_space is not None:
            self._detect_loss(now=now)
        else:
            self.pto_count += 1
            self.reschedule_data(now=now)

    def on_packet_sent(self, packet: SentPacket) -> None:
        self.space.sent_packets[packet.pn] = packet

        if packet.ack_eliciting:
            self.space.ack_eliciting_in_flight += 1
            self.space.ack_eliciting_bytes_in_flight += packet.size
        if packet.in_flight:
            if packet.ack_eliciting:
                self._time_of_last_sent_ack_eliciting_packet = packet.time_sent

            # TODO: add packet to bytes in flight
            # self._cc.on_packet_sent(packet=packet)

            # if self._quic_logger is not None:
            #     self._log_metrics_updated()

    def reschedule_data(self, *, now: float) -> None:
        """
        Schedule some data for retransmission.
        """
        # if there is any outstanding CRYPTO, retransmit it
        crypto_scheduled = False
        packets = tuple(
            filter(lambda i: i.is_crypto_packet, self.space.sent_packets.values())
        )
        if packets:
            self._on_packets_lost(now=now, packets=packets)
            crypto_scheduled = True
        # if crypto_scheduled and self._logger is not None:
        #     self._logger.debug("Scheduled CRYPTO data for retransmission")

        # ensure an ACK-eliciting packet is sent
        self._send_probe()

    def _detect_loss(self, now: float) -> None:
        """
        Check whether any packets should be declared lost.
        """
        loss_delay = K_TIME_THRESHOLD * (
            max(self._rtt_latest, self._rtt_smoothed)
            if self._rtt_initialized
            else self._rtt_initial
        )
        packet_threshold = self.space.largest_acked_packet - K_PACKET_THRESHOLD
        time_threshold = now - loss_delay

        lost_packets = []
        self.space.loss_time = None
        for packet_number, packet in self.space.sent_packets.items():
            if packet_number > self.space.largest_acked_packet:
                break

            if packet_number <= packet_threshold or packet.time_sent <= time_threshold:
                lost_packets.append(packet)
            else:
                packet_loss_time = packet.time_sent + loss_delay
                if self.space.loss_time is None or self.space.loss_time > packet_loss_time:
                    self.space.loss_time = packet_loss_time

        self._on_packets_lost(now=now, packets=lost_packets)

    def _get_loss_space(self) -> PacketNumberSpace | None:
        return self.space if self.space.loss_time is not None else None

    def _log_metrics_updated(self, log_rtt=False) -> None:
        data: Dict[str, Any] = self._cc.get_log_data()

        if log_rtt:
            data.update(
                {
                    "latest_rtt": self._quic_logger.encode_time(self._rtt_latest),
                    "min_rtt": self._quic_logger.encode_time(self._rtt_min),
                    "smoothed_rtt": self._quic_logger.encode_time(self._rtt_smoothed),
                    "rtt_variance": self._quic_logger.encode_time(self._rtt_variance),
                }
            )

        self._quic_logger.log_event(
            category="recovery", event="metrics_updated", data=data
        )

    def _on_packets_lost(self, *, now: float, packets: Iterable[SentPacket]) -> None:
        lost_packets_cc = []
        for packet in packets:
            del self.space.sent_packets[packet.pn]

            if packet.in_flight:
                lost_packets_cc.append(packet)

            if packet.ack_eliciting:
                self.space.ack_eliciting_in_flight -= 1
                self.space.ack_eliciting_bytes_in_flight -= packet.size

            # if self._quic_logger is not None:
            #     self._quic_logger.log_event(
            #         category="recovery",
            #         event="packet_lost",
            #         data={
            #             "type": self._quic_logger.packet_type(packet.packet_type),
            #             "packet_number": packet.packet_number,
            #         },
            #     )
            #     self._log_metrics_updated()

            # trigger callbacks
            # for handler, args in packet.delivery_handlers:
            #     handler(QuicDeliveryState.LOST, *args)

        # inform congestion controller
        if lost_packets_cc:
            self._cc.on_packets_lost(now=now, packets=lost_packets_cc)
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )
            if self._quic_logger is not None:
                self._log_metrics_updated()
