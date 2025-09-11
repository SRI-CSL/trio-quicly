#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from enum import Enum, auto
from dataclasses import dataclass
import secrets
import trio
from types import TracebackType
from typing import *

from .acks import PacketNumberTracker, SentPacket, RttState
from .configuration import QuicConfiguration, SMALLEST_MAX_DATAGRAM_SIZE, PARAM_SCHEMA
from .exceptions import QuicErrorCode
from .frame import decode_var_length_int, QuicFrame, QuicFrameType, ConfigFrame, TransportParameter, \
    ConnectionCloseFrame
from .logger import make_qlog
from .packet import create_quic_packet, is_long_header, QuicPacketType, LongHeaderPacket, \
    MAX_UDP_PACKET_SIZE, decode_udp_packet, QuicProtocolVersion, QuicPacket
from .trio_timer import TrioTimer
from .utils import _Queue, AddressFormat, hexdump

NetworkAddress = Any

def get_dcid_from_header(data: bytes, cid_length: int) -> Optional[bytes]:
    """
    Try to parse CID from header (scid from INITIAL, dcid from 1-RTT)
    :param data: payload bytes of a QUIC Packet
    :param cid_length: length of CID (needed for short headers
    :return: connection ID, if parsing succeeded
    """
    if len(data) < 2:
        return None
    if is_long_header(data[0]):  # long header
        if len(data) < 5:
            return None
        if (data[0] & 0xFC) != 0xC0 or data[1:5] != QuicProtocolVersion.QUICLY.to_bytes(4, "big"):
            # 1. byte did not start with "110000" or QUIC-LY version number didn't match
            return None
        dcid_length, _ = decode_var_length_int(data[5:])
        if len(data) < 5 + dcid_length + 1:
            return None
        scid_length, _ = decode_var_length_int(data[5 + dcid_length + 1:])
        if len(data) < 5 + dcid_length + 1 + scid_length:
            return None
        return data[5 + dcid_length + 2:5 + dcid_length + 2 + scid_length]
    else:  # short header
        if len(data) < 1 + cid_length or cid_length <= 0:
            return None
        if (data[0] & 0xD8) != 0x40:
            return None
        return data[1:1 + cid_length]


@dataclass
class QuicConnectionId:
    cid: bytes
    sequence_number: Optional[int]
    stateless_reset_token: bytes = b""
    was_sent: bool = False

class ConnectionState(Enum):
    # client-only
    START = auto()
    WAIT_FIRST = auto()
    # server-only
    LISTEN = auto()
    # shared
    ESTABLISHED = auto()
    CLOSING = auto()
    DRAINING = auto()

# @final
# TODO: first approximation is to simply match 1 QUIC connection without handshake to 1 QUIC bidi stream
class SimpleQuicConnection(trio.abc.Stream):
    def __init__(self,
                 sending_ch: trio.MemorySendChannel[tuple[bytes, tuple[str, int]]],
                 remote_address: NetworkAddress,
                 connection_id_length: int,
                 incoming_packets_buffer: int,
                 configuration: QuicConfiguration,
                 ) -> None:
        """
        Connection
        : A QUIC Connection is shared state between a client and a server. Connection IDs allow Connections to migrate
        to a new network path, both as a direct choice of an endpoint and when forced by a change in a middlebox.

        :param configuration:
        """

        assert sending_ch is not None, "Cannot create QUIC connection without sending channel"
        self.sending_ch = sending_ch

        assert configuration.max_datagram_size >= SMALLEST_MAX_DATAGRAM_SIZE, (
            f"The smallest allowed maximum datagram size is {SMALLEST_MAX_DATAGRAM_SIZE} bytes"
        )
        self._configuration = configuration
        self._is_client = configuration.is_client
        self.remote_address: AddressFormat = remote_address
        assert self.remote_address is not None

        # state management:
        self._closed = False
        self._did_handshake = False  # after successful handshake, connection is ESTABLISHED
        self._handshake_lock = trio.Lock()  # guard handshake
        self.state = ConnectionState.START if self._is_client else ConnectionState.LISTEN

        # connection IDs:
        self._host_cids = [
            QuicConnectionId(
                cid=secrets.token_bytes(connection_id_length),
                sequence_number=0,
                stateless_reset_token=secrets.token_bytes(16) if not self._is_client else None,
                was_sent=True,
            )
        ]
        self.host_cid = self._host_cids[0].cid
        self._host_cid_seq = 1
        self.peer_cid = QuicConnectionId(
            cid=secrets.token_bytes(connection_id_length),  # random bits until handshake completed
            sequence_number=None
        )
        # self._peer_cid_available: List[QuicConnectionId] = []
        # self._peer_cid_sequence_numbers: Set[int] = {0}
        # self._peer_retire_prior_to = 0

        # TODO: packet numbers and ACKs:
        self._next_pn_tx = {
            QuicPacketType.INITIAL: 0,
            QuicPacketType.ONE_RTT: 0,
        }
        # # Optional: whether an ACK is pending in each space
        # self._ack_needed_initial = False
        # self._ack_needed_1rtt    = False
        # Per-space sender state
        self._sent_map: Dict[QuicPacketType, Dict[int, SentPacket]] = {
            QuicPacketType.INITIAL: {},
            QuicPacketType.ONE_RTT: {},
        }
        self.bytes_in_flight: int = 0
        self.pto_timers = {  # TODO: callback functions!
            QuicPacketType.INITIAL: TrioTimer(),
            QuicPacketType.ONE_RTT: TrioTimer(),
        }
        # self.pto_tasks = {space: None}
        # self.pto_count = {
        #     PNSpace.INITIAL: 0,
        #     PNSpace.ONE_RTT: 0,
        # }
        self._pns_rx = {  # track received packet numbers by space
            QuicPacketType.INITIAL: PacketNumberTracker(),
            QuicPacketType.ONE_RTT: PacketNumberTracker()
        }

        # Round-Trip-Times TODO: move to loss detection and congestion control later
        self._rtt_state: Dict[QuicPacketType, RttState] = {
            QuicPacketType.INITIAL: RttState(),
            QuicPacketType.ONE_RTT: RttState(),
        }
        # Loss / PTO knobs (reasonable defaults)
        self.k_packet_threshold = 3  # RFC 9002
        self.k_time_threshold = 1.125  # 9/8
        self.k_granularity = 0.001  # 1ms
        self.max_ack_delay_ms = 8  # Initial space: 8ms; 1-RTT: from transport param

        self._q = _Queue[bytes](incoming_packets_buffer)
        self._loops_spawned = False
        self._qlog = make_qlog("client" if self._is_client else "server", category="transport").bind(
            odcid_hex=hexdump(self.host_cid))

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Close this connection.

        `QuicConnections`\\s don't actually own any OS-level resources – the
        socket is owned by the `QuicEndpoint`, not the individual connections. So
        you don't really *have* to call this. But it will interrupt any other tasks
        calling `receive` with a `ClosedResourceError`, and cause future attempts to use
        this connection to fail.

        You can also use this object as a synchronous or asynchronous context manager.
        """
        if self._closed:
            return
        self._closed = True
        self.sending_ch.close()
        # TODO: how to communicate to Endpoint?
        # if self.endpoint.connections.get(self.remote_address) is self:
        #     del self.endpoint.connections[self.remote_address]

        # Will wake any tasks waiting on self.q.r.receive() with a ClosedResourceError:
        self._q.r.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return self.close()

    async def aclose(self) -> None:
        """Close this connection, but asynchronously.
        This is included to satisfy the `trio.abc.Stream` contract. It's
        identical to `close`, but async.
        """
        self.close()
        await trio.lowlevel.checkpoint()

    def start_background(self, nursery: trio.Nursery) -> None:
        nursery.start_soon(self.pto_timers[QuicPacketType.INITIAL].timer_loop, )
        nursery.start_soon(self.pto_timers[QuicPacketType.ONE_RTT].timer_loop, )

    # def _arm_pto(self, space, now):
    #     if not self._ack_eliciting_in_flight(space):
    #         self.pto_deadline[space] = None
    #         if self._pto_event[space].statistics().tasks_waiting:  # optional
    #             self._pto_event[space].set()
    #         return
    #     base = self._compute_pto(space)  # srtt + max(4*var, granularity) + max_ack_delay
    #     eff = base * (2 ** self.pto_count[space])  # backoff
    #     self.pto_deadline[space] = now + eff
    #     self._pto_event[space].set()  # wake loop to re-schedule
    #
    # async def _on_pto_fire(self, space):
    #     # Send a probe (Initial: retransmit CONFIG; 1-RTT: any ack-eliciting probe)
    #     self._send_probe(space)
    #     self.pto_count[space] += 1
    #     # Re-arm based on new now:
    #     self._arm_pto(space, trio.current_time())

    def _get_and_incr_pn(self, space: QuicPacketType) -> int:
        next_pn = self._next_pn_tx[space]
        self._next_pn_tx[space] = next_pn + 1
        return next_pn

    # def _update_rtt(self, space: PNSpace, latest: float, ack_delay: float) -> None:
    #     rs = self._rtt_state[space]
    #     # Handshake spaces ignore ack_delay; 1-RTT may subtract min(ack_delay, max_ack_delay)
    #     adj = latest if ack_delay <= 0 else max(latest - ack_delay, self.k_granularity)
    #     if rs.srtt is None:
    #         rs.srtt = adj
    #         rs.rttvar = adj / 2
    #     else:
    #         rs.rttvar = (3 / 4) * rs.rttvar + (1 / 4) * abs(rs.srtt - adj)
    #         rs.srtt = (7 / 8) * rs.srtt + (1 / 8) * adj
    #     rs.latest = latest
    #
    # def _detect_losses(self, space: PNSpace, largest_acked: int, now: float) -> None:
    #     sent_map = self._sent_map[space]
    #     if not sent_map:
    #         return
    #
    #     rs = self._rtt_state[space]
    #     base_rtt = (rs.srtt or rs.latest or 0.0)
    #     time_thresh = self.k_time_threshold * max(base_rtt, self.k_granularity)
    #     pkt_thresh = self.k_packet_threshold
    #
    #     lost: List[int] = []
    #     for pn, sp in sent_map.items():
    #         # Packet threshold
    #         if pn <= largest_acked - pkt_thresh:
    #             lost.append(pn)
    #             continue
    #         # Time threshold
    #         if base_rtt and now - sp.time_sent > time_thresh:
    #             lost.append(pn)
    #
    #     for pn in lost:
    #         sp = sent_map.pop(pn)
    #         if sp.in_flight:
    #             self.bytes_in_flight -= sp.size
    #         self._on_packet_lost(space, sp)  # schedule retransmission of 'sp.frames' as appropriate
    #
    # def _on_ecn_counts(self, space: PNSpace, ecn: ECNCounts) -> None:
    #     # Keep previous counts per path and compare deltas; if CE increased, apply CC reaction.
    #     # Stub for now; integrate with your congestion controller if present.
    #     pass
    #
    # def _apply_ack(self, space: PNSpace, ack: ACKFrame, now: float) -> None:
    #     intervals = ack_to_intervals(ack)  # [(low, high)] descending by high
    #     if not intervals:
    #         return
    #
    #     sent_map = self._sent_map[space]
    #     if not sent_map:
    #         # Nothing in flight (pure duplicate/late ACK) -> ignore gracefully
    #         return
    #
    #     # Collect newly-acked PNs we actually have in-flight
    #     def is_acked(pn: int) -> bool:
    #         # intervals are few; linear check is fine
    #         for lo, hi in intervals:
    #             if lo <= pn <= hi:
    #                 return True
    #         return False
    #
    #     acked_pns = [pn for pn in list(sent_map.keys()) if is_acked(pn)]
    #     if not acked_pns:
    #         # No new info; could be a duplicate ACK
    #         return
    #
    #     largest_newly_acked = max(acked_pns)
    #     rtt_sample = None
    #
    #     # Remove from flight & maybe take RTT sample
    #     for pn in acked_pns:
    #         sp = sent_map.pop(pn)
    #         if sp.in_flight:
    #             self.bytes_in_flight -= sp.size
    #         # Use the largest newly-acked, ack-eliciting packet for RTT
    #         if pn == largest_newly_acked and sp.ack_eliciting:
    #             rtt_sample = max(now - sp.time_sent, self.k_granularity)
    #
    #     # Update RTT (Initial uses max_ack_delay=0)
    #     if rtt_sample is not None:
    #         ack_delay = (0 if space is PNSpace.INITIAL else max(0,
    #                                                             ack.ack_delay))  # you may need to unscale by 2^ack_delay_exponent depending on units
    #         self._update_rtt(space, rtt_sample, ack_delay / 1_000_000.0)  # if ack_delay is in us
    #
    #     # Loss detection for older packets
    #     self._detect_losses(space, largest_newly_acked, now)
    #
    #     # (Optional) ECN processing
    #     if ack.ecn_counts is not None:
    #         self._on_ecn_counts(space, ack.ecn_counts)
    #
    #     # Re-arm/cancel PTO per RFC 9002 (not shown here; depends on your timer wiring)
    #     self._rearm_pto(space, now)

    def init_handshake(self) -> QuicPacket:
        ts = [TransportParameter(*tp) for tp in self.configuration.transport_parameters.as_list(exclude_defaults=True)]
        client_config_frame = QuicFrame(QuicFrameType.CONFIG,
                                        content=ConfigFrame(ts))
        return create_quic_packet(QuicPacketType.INITIAL,
                                  destination_cid=b'',  # don't need random bits in QUIC-LY!
                                  source_cid=self.host_cid,
                                  packet_number=self._get_and_incr_pn(QuicPacketType.INITIAL),
                                  payload=[client_config_frame])

    async def on_tx(self, qpkt: QuicPacket, timeout: float = 0.0) -> None:
        data = qpkt.encode_all_bytes()
        # update sent map (for correct PN space)
        sp = SentPacket(
            qpkt.packet_number,
            time_sent=trio.current_time(),
            ack_eliciting=qpkt.is_ack_eliciting(),
            in_flight=True
        )
        self._sent_map[qpkt.packet_type][sp.pn] = sp
        # if ack-eliciting: arm or re-arm PTO timer
        if sp.ack_eliciting:
            pto_timer = self.pto_timers[qpkt.packet_type]
            assert timeout > 0  # TODO: log error
            pto_timer.set_timer_after(timeout)
        self._qlog.info("Packet sent", data={"header": {"packet_type": qpkt.packet_type,
                                                        "packet_number": qpkt.packet_number,
                                                        # TODO: use convenience methods from qlog.py
                                                        }})
        # submit to endpoint for sending as bytes payload:
        if qpkt.packet_type == QuicPacketType.INITIAL and self._is_client:
            # Any datagram sent by the client that contains an Initial packet must be padded to a length of
            # INITIAL_PADDING_TARGET bytes. This library does it by appending nul bytes to the datagram.
            data = data.ljust(self.configuration.transport_parameters.initial_padding_target, b'\x00')
        await self.send_all(data)

    async def do_handshake(self, hello_payload: bytes, remote_address: NetworkAddress,
                           data_payload: bytes = None) -> bool:
        """Perform the handshake.

        It's safe to call this multiple times, or call it simultaneously from multiple
        tasks – the first call will perform the handshake, and the rest will be no-ops.

        Args:
          hello_payload (bytes): this encodes the INITIAL QuicPacket; if we are the
            client side, then the initial connection ID should match the payload.
            TODO: how to react if it doesn't match?
            If we are the server, then are about to respond with our INITIAL QuicPacket.
          data_payload: Optional stream or datagram payload to be sent with initial packet.
            Only useful from client side as it will be ignored from the server side.
            TODO: what does this mean for QUIC-LY? Can't we already initiate with STREAM (or DATAGRAM) payload?

        """
        async with (self._handshake_lock):  # TODO: check await's under this for blocking this top-level with()
            if self._did_handshake:
                return True

            try:
                hello_packets = list(decode_udp_packet(hello_payload))
                assert len(hello_packets) >= 1  # If there are more QUIC packets, silently drop them
                if self._is_client:
                    server_initial_pkt = hello_packets[0]
                    assert server_initial_pkt.packet_type == QuicPacketType.INITIAL, "while in handshake, only expect INITIAL"
                    assert server_initial_pkt.destination_cid == self.host_cid, "initial packet destination CID must be the same as my source CID"
                    assert server_initial_pkt.version == QuicProtocolVersion.QUICLY, "initial packet version must be QUICLY"

                    await self.on_rx([server_initial_pkt], remote_address)

                    # parse ACK frames:
                    # for ack in iter_ack_frames(server_initial_pkt.payload):  # yields ACKFrame (handles ACK_ECN too)
                    #     self._apply_ack(PNSpace.INITIAL, ack, now=)

                    # find last CONFIG_ACK frame in payload (if any):
                    last_cfg_ack = next((f for f in reversed(server_initial_pkt.payload)
                                         if f.frame_type == QuicFrameType.CONFIG_ACK), None)
                    if last_cfg_ack:
                        assert isinstance(last_cfg_ack.content, ConfigFrame)
                        server_params = {PARAM_SCHEMA[tp.param_id][0]: tp.value
                                         for tp in last_cfg_ack.content.transport_parameters}
                        self.configuration.transport_parameters.update(server_params)

                    if data_payload:  # any STREAM or DATAGRAM payload to immediately send?
                        # TODO: client_stream_frame = QuicFrame(QuicFrameType.STREAM_BASE,
                        #                                 content=StreamFrame(stream_id=0, data=stream_payload))
                        client_packet = create_quic_packet(QuicPacketType.ONE_RTT,
                                                           destination_cid=server_initial_pkt.source_cid,
                                                           spin_bit=False, key_phase=False,
                                                           packet_number=0,
                                                           payload=[QuicFrame(QuicFrameType.PADDING)])
                        await self.on_tx(client_packet, 2.0)  # TODO: calculate proper PTO

                else:  # server-side of handshake
                    client_initial_pkt = hello_packets[0]
                    assert client_initial_pkt.packet_type == QuicPacketType.INITIAL, "initial packet type must be INITIAL"
                    if client_initial_pkt.version != QuicProtocolVersion.QUICLY:
                        # If a server refuses to accept a new connection, it SHOULD send an Initial packet containing
                        #  a CONNECTION_CLOSE frame with error code CONNECTION_REFUSED.
                        refused_frame = ConnectionCloseFrame(QuicErrorCode.CONNECTION_REFUSED,
                                                             reason=b'')
                        refused_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                         destination_cid=client_initial_pkt.source_cid,
                                                         source_cid=b'',  # no need to expend CID
                                                         packet_number=0,
                                                         payload=[QuicFrame(QuicFrameType.TRANSPORT_CLOSE,
                                                                            content=refused_frame)])
                        await self.on_tx(refused_pkt)  # not ack-eliciting, so no timeout needed
                        return False

                    await self.on_rx([client_initial_pkt], remote_address)

                    # ACK immediately: Cap ranges to something reasonable; 8 is fine
                    payload = [self._pns_rx[QuicPacketType.INITIAL].to_ack_frame(
                        frame_type=QuicFrameType.ACK,
                        ack_delay_us=8,  # must be >= 8
                        max_ranges=8,
                    )]

                    # find last CONFIG frame in payload:
                    last_cfg = next((f for f in reversed(client_initial_pkt.payload)
                                     if f.frame_type == QuicFrameType.CONFIG), None)
                    assert last_cfg is not None
                    assert isinstance(last_cfg.content, ConfigFrame)
                    # TODO: what are the semantics of receiving client parameters? Should they always override servers'?
                    client_params = {PARAM_SCHEMA[tp.param_id][0]: tp.value
                                     for tp in last_cfg.content.transport_parameters}
                    if self.configuration.transport_parameters.update(client_params):
                        ts = [TransportParameter(*tp) for tp in
                              self.configuration.transport_parameters.as_list(exclude_defaults=True)]
                        payload.append(QuicFrame(QuicFrameType.CONFIG_ACK,
                                                 content=ConfigFrame(ts)))

                    server_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                            destination_cid=client_initial_pkt.source_cid,  # repeated back
                                                            source_cid=self.host_cid,
                                                            packet_number=self._get_and_incr_pn(QuicPacketType.INITIAL),
                                                            payload=payload)
                    await self.on_tx(server_initial_pkt, 2.0)  # TODO: calculate from RTT for ONE_RTT space!

            except AssertionError as ae:
                raise ae  # TODO: remove after testing
                # TODO: turn assertion errors into PROTOCOL_VIOLATION, QLog?
                return False
            self.remote_address = remote_address  # potentially overwrite client's initial target address
            self.state = ConnectionState.ESTABLISHED
            self._did_handshake = True
            return True

    async def on_rx(self, quic_packets: List[QuicPacket], remote_addr: NetworkAddress = None) -> None:
        """
        Parse UDP payload into QUIC packets and frames to be handled.  Payload of any STREAM or DATAGRAM frames then
        gets forwarded to self.q.s.send(payload) for users of this QUIC connection to receive data.
        """
        # TODO: check network path with `remote_addr`?

        for qp in quic_packets:
            # housekeeping with QUIC header info:
            if not (qp.packet_type == QuicPacketType.INITIAL and not self._is_client):
                # INITIAL at server has not established CID:
                assert qp.destination_cid == self.host_cid  # TODO: once we migrate or have more CIDs...
            self._pns_rx[qp.packet_type].note_received(qp.packet_number)
            if qp.packet_type == QuicPacketType.INITIAL:
                assert len(qp.payload) > 0
                assert self.peer_cid.sequence_number is None, "not first INITIAL packet received"
                init_pkt = cast(LongHeaderPacket, qp)
                self.peer_cid = QuicConnectionId(init_pkt.source_cid, 0, was_sent=True)
            # now handle each frame (if present):
            for qf in qp.payload:
                pass
                # TODO: when handling STREAM or DATAGRAM frames: forward their data payload to user of connection:
                # await connection._q.s.send(stream_payload)


    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        """
        Schedules this data blob for sending at endpoint.
        """
        if self._closed:
            raise trio.ClosedResourceError("connection was already closed")
        # TODO: if QUIC Streams are also HalfClosable then do more state checking here...?
        await self.sending_ch.send((data, self.remote_address))

    async def wait_send_all_might_not_block(self) -> None:
        """Block until it's possible that :meth:`send_all` might not block.

        This method may return early: it's possible that after it returns,
        :meth:`send_all` will still block. (In the worst case, if no better
        implementation is available, then it might always return immediately
        without blocking. It's nice to do better than that when possible,
        though.)

        This method **must not** return *late*: if it's possible for
        :meth:`send_all` to complete without blocking, then it must
        return. When implementing it, err on the side of returning early.

        Raises:
          trio.BusyResourceError: if another task is already executing a
              :meth:`send_all`, :meth:`wait_send_all_might_not_block`, or
              :meth:`HalfCloseableStream.send_eof` on this stream.
          trio.BrokenResourceError: if something has gone wrong, and the stream
              is broken.
          trio.ClosedResourceError: if you previously closed this stream
              object, or if another task closes this stream object while
              :meth:`wait_send_all_might_not_block` is running.

        Note:

          This method is intended to aid in implementing protocols that want
          to delay choosing which data to send until the last moment. E.g.,
          suppose you're working on an implementation of a remote display server
          like `VNC
          <https://en.wikipedia.org/wiki/Virtual_Network_Computing>`__, and
          the network connection is currently backed up so that if you call
          :meth:`send_all` now then it will sit for 0.5 seconds before actually
          sending anything. In this case it doesn't make sense to take a
          screenshot, then wait 0.5 seconds, and then send it, because the
          screen will keep changing while you wait; it's better to wait 0.5
          seconds, then take the screenshot, and then send it, because this
          way the data you deliver will be more
          up-to-date. Using :meth:`wait_send_all_might_not_block` makes it
          possible to implement the better strategy.

        """
        if self.is_closed:
            raise trio.ClosedResourceError("Can no longer sent as connection closed")
        while self.sending_ch.statistics().current_buffer_used:
            await trio.sleep(0.001)

    async def receive_some(self, max_bytes: int | None = None) -> bytes | None:
        if self._closed:
            raise trio.ClosedResourceError("connection was already closed")

        if max_bytes is None:
            max_bytes = MAX_UDP_PACKET_SIZE
        if max_bytes < 1:
            raise ValueError("max_bytes must be >= 1")
        try:
            packet = await self._q.r.receive()
            return packet[:max_bytes]
        except (trio.EndOfChannel, trio.ClosedResourceError):
            # we catch ClosedResource here as it comes from the Queue being closed
            return b""

    # def create_stream(self, bidirectional: bool = True) -> QuicStream:
    #     return QuicBidiStream() if bidirectional else QuicSendStream()
    #     # # TODO: while testing with TCP:
    #     # assert (self._is_client and self._connect_called)
    #     # return await trio.open_tcp_stream(self.host, self.port)
    #
    # def accept_stream(self, bidirectional: bool = True) -> QuicStream:
    #     return QuicBidiStream() if bidirectional else QuicReceiveStream()
