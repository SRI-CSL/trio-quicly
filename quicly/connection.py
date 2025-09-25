#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
from enum import Enum, auto
from dataclasses import dataclass
import math
import secrets
import trio
from types import TracebackType
from typing import *

from .acks import PacketNumberSpace, SentPacket
from .configuration import QuicConfiguration, SMALLEST_MAX_DATAGRAM_SIZE, PARAM_SCHEMA
from .exceptions import QuicErrorCode
from .frame import decode_var_length_int, QuicFrame, QuicFrameType, ConfigFrame, TransportParameter, \
    ConnectionCloseFrame, ACKFrame, NON_ACK_ELICITING_FRAME_TYPES
from .logger import make_qlog
from .packet import create_quic_packet, is_long_header, QuicPacketType, LongHeaderPacket, \
    MAX_UDP_PACKET_SIZE, decode_udp_packet, QuicProtocolVersion, QuicPacket
from .recovery import QuicPacketRecovery
from .trio_timer import TrioTimer
from .utils import _Queue, AddressFormat, hexdump, K_MILLI_SECOND

NetworkAddress = Any

def get_cid_from_header(data: bytes, cid_length: int = 0) -> Optional[bytes]:
    """
    Try to parse CID from header (scid from INITIAL, dcid from 1-RTT)
    :param data: payload bytes of a QUIC Packet
    :param cid_length: length of CID (needed for short headers)
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
        if cid_length <= 0:
            return None
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
    LISTEN = auto()
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
        self._idle_timer = TrioTimer("client" if self._is_client else "server", callback_fn=self.send_closing, )
        self.state = ConnectionState.LISTEN

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
            cid=b'',
            sequence_number=None  # None until first INITIAL packet processed
        )
        # self._peer_cid_available: List[QuicConnectionId] = []
        # self._peer_cid_sequence_numbers: Set[int] = {0}
        # self._peer_retire_prior_to = 0

        # packet numbers and ACKs:
        self._next_pn_tx = 0
        self.pto_timer = TrioTimer("client" if self._is_client else "server", callback_fn=self.send_probe, )
        # track received packet numbers by space:
        self._pn_space = PacketNumberSpace()
        self._ack_timer = TrioTimer("client" if self._is_client else "server", self.send_acks, )
        # loss recovery
        self._loss = QuicPacketRecovery(
            # congestion_control_algorithm=configuration.congestion_control_algorithm,
            # max_datagram_size=self._max_datagram_size,
            peer_completed_address_validation=not self._is_client,
            space=self._pn_space,
        )

        # allowing timer callbacks to trigger async transmissions:
        self.on_tx_send, self.on_tx_recv = trio.open_memory_channel(math.inf)  # buffer indefinitely
        self._q = _Queue[bytes](incoming_packets_buffer)
        self._loops_spawned = False

        self._qlog = make_qlog("client" if self._is_client else "server", category="transport").bind(
            current_state=lambda: self.state, odcid_hex=lambda: hexdump(self.host_cid))

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def is_closing(self) -> bool:
        return self.state in [ConnectionState.DRAINING, ConnectionState.CLOSING]

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
        This is included to satisfy the `trio.abc.Stream` contract. It's identical to `close`, but async.
        """
        self.close()
        await trio.lowlevel.checkpoint()

    async def _on_tx_loop(self):
        async with self.on_tx_recv:
            async for pt, payload in self.on_tx_recv:
                if pt == QuicPacketType.INITIAL:
                    qpkt = create_quic_packet(pt,
                                              destination_cid=self.peer_cid.cid,
                                              source_cid=self.host_cid,
                                              packet_number=self._get_and_incr_pn(),
                                              payload=payload, )
                else:
                    assert self.peer_cid.cid, "sending ONE_RTT before destination CID known"
                    qpkt = create_quic_packet(pt,
                                              destination_cid=self.peer_cid.cid,
                                              packet_number=self._get_and_incr_pn(),
                                              payload=payload, )
                await self.on_tx(qpkt)

    def start_background(self, nursery: trio.Nursery) -> None:
        nursery.start_soon(self._idle_timer.timer_loop, )
        nursery.start_soon(self.pto_timer.timer_loop, )
        nursery.start_soon(self._ack_timer.timer_loop, )
        nursery.start_soon(self._on_tx_loop, )

    async def enter_closing(self) -> None:
        if self.state == ConnectionState.ESTABLISHED:
            # try to send one more CONNECTION_CLOSE:
            close_frame = ConnectionCloseFrame(QuicErrorCode.APPLICATION_ERROR,
                                               reason=b'aclose()')  # APP_CLOSE does not include frame type!
            await self.on_tx(
                create_quic_packet(QuicPacketType.ONE_RTT,
                                   self.peer_cid.cid,
                                   packet_number=self._get_and_incr_pn(),
                                   payload=[QuicFrame(QuicFrameType.APPLICATION_CLOSE, content=close_frame)]))
        await self.aclose()

    def enter_draining(self) -> None:
        self.state = ConnectionState.DRAINING
        # cancel timers
        self._ack_timer.cancel()
        self._idle_timer.cancel()
        self.pto_timer.cancel()

    def _get_and_incr_pn(self) -> int:
        next_pn = self._next_pn_tx
        self._next_pn_tx = next_pn + 1
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

    def _rearm_pto(self) -> None:
        """
        Call at the end of ACK processing for `space` or when PTO expires.
        """
        loss_detection_time = self._loss.get_loss_detection_time()
        if loss_detection_time is None:  # Nothing in flight -> no PTO for this space
            self.pto_timer.cancel()
        else:
            self.pto_timer.set_timer_at(loss_detection_time)

    def _get_config_frame(self) -> QuicFrame:
        ts = [TransportParameter(*tp) for tp in self.configuration.transport_parameters.as_list(exclude_defaults=True)]
        return QuicFrame(QuicFrameType.CONFIG if self._is_client else QuicFrameType.CONFIG_ACK,
                         content=ConfigFrame(ts))

    def init_handshake(self) -> QuicPacket:
        return create_quic_packet(QuicPacketType.INITIAL,
                                  destination_cid=b'',  # don't need random bits in QUIC-LY!
                                  source_cid=self.host_cid,
                                  packet_number=self._get_and_incr_pn(),
                                  payload=[self._get_config_frame()])

    async def on_tx(self, qpkt: QuicPacket) -> None:
        if self.is_closed:
            self._qlog.debug(f"Attempting to send QUIC packet after connection closed - dropping.", packet=qpkt)
            return

        possible_ack_frame = self._pn_space.to_ack_frame(QuicFrameType.ACK, now=trio.current_time())
        if possible_ack_frame is not None:
            qpkt.payload.append(possible_ack_frame)
            # When PNSpace._intervals grows beyond a threshold, call drop_acked_up_to(cutoff) where cutoff
            # is the high end of the N-th most recent interval we still want to retain. This keeps memory
            # bounded and still re-advertises recent history if prior ACKs were lost.
            N = self.configuration.max_ack_intervals
            if N == 0:  # drop everything
                self._pn_space.drop_acked_up_to(self._pn_space.largest_acked_packet)
            elif len(self._pn_space) > N:
                older = self._pn_space[:-N]  # ascending by low: everything before last N is older
                self._pn_space.drop_acked_up_to(older[-1][1])  # cutoff is HIGH of the last older interval

        if len(qpkt.payload) == 0:
            return  # by now, we should have at least one frame; if not, this was a timer expiring but no action items

        data = qpkt.encode_all_bytes()
        sp = SentPacket(
            qpkt.packet_number,
            time_sent=trio.current_time(),
            size=len(data),
            ack_eliciting=qpkt.is_ack_eliciting(),
            in_flight=True,
            is_initial=(qpkt.packet_type == QuicPacketType.INITIAL),
            frames=[fr for fr in qpkt.payload if fr.frame_type in NON_ACK_ELICITING_FRAME_TYPES]
        )
        self._qlog.debug(f"*** on_tx()", sp=sp)  # TODO: remove after implementing proper QLOG below
        self._loss.on_packet_sent(packet=sp)
        if sp.ack_eliciting:  # ack-eliciting and in-flight
            self._rearm_pto()
            if self._pn_space.last_successful_rx is not None:
                # restart idle timeout if sending the first ack-eliciting packet since the last successful RX
                self._idle_timer.set_timer_after(max(
                    self.configuration.transport_parameters.idle_timeout_ms * K_MILLI_SECOND,
                    3 * self._loss.get_probe_timeout()))
                self._pn_space.last_successful_rx = None

        self._qlog.info("Packet sent",
                        size=len(data),
                        data={"header": {"packet_type": str(qpkt.packet_type),
                                         "packet_number": qpkt.packet_number,
                                                        # TODO: use convenience methods from qlog.py
                                         }})

        if qpkt.packet_type == QuicPacketType.INITIAL and self._is_client:
            # Any datagram sent by the client that contains an Initial packet must be padded to a length of
            # INITIAL_PADDING_TARGET bytes. This library does it by appending nul bytes to the datagram.
            data = data.ljust(self.configuration.transport_parameters.initial_padding_target, b'\x00')
        await self.send_all(data, qpkt.is_closing())

    def send_probe(self) -> None:
        if self.is_closing:
            self._qlog.info(f"PTO Timer expired but connection is closing, so ignoring.")
            return

        if self.state == ConnectionState.ESTABLISHED:
            pt = QuicPacketType.ONE_RTT
            additional_payload = [QuicFrame(QuicFrameType.PING)]
        else:
            pt = QuicPacketType.INITIAL
            additional_payload = [self._get_config_frame()]  # CONFIG/CONFIG_ACK

        try:  # trigger on_tx() through memory channel:
            self.on_tx_send.send_nowait((pt, additional_payload))
        except trio.WouldBlock:
            self._qlog.warn(f"*** WouldBlock (send_probe) triggered and prevented tx_send signal at {trio.current_time():.3f}",
                            stats=self.on_tx_send.statistics())
            pass  # ignore if buffer is full, which should not happen at infinite capacity

        # when re-arming timer, exponentially back-off:
        self._loss.pto_count += 1
        self._qlog.debug(f"Increasing PTO count to {self._loss.pto_count}")

    def send_acks(self, pt: QuicPacketType = QuicPacketType.ONE_RTT,
                  additional_payload: list[QuicFrame] | None = None) -> None:
        if additional_payload is None:
            additional_payload = []
        if self.is_closing:
            self._qlog.info(f"ACK delay timer expired but connection is closing, so ignoring.")
            return

        # only servers send ACKs in INITIAL to respond to INITIAL, otherwise use 1-RTT:
        pt = QuicPacketType.INITIAL if pt == QuicPacketType.INITIAL and not self._is_client else QuicPacketType.ONE_RTT
        try:  # trigger on_tx() through memory channel:
            self.on_tx_send.send_nowait((pt, additional_payload))
        except trio.WouldBlock:
            self._qlog.warn(f"*** WouldBlock (send_acks) triggered and prevented tx_send signal at {trio.current_time():.3f}",
                            stats=self.on_tx_send.statistics())
            pass  # ignore if buffer is full, which should not happen at infinite capacity

    def send_closing(self, payload: list[QuicFrame] | None = None) -> None:
        if self.is_closing:
            self._qlog.info(f"Connection is already closing, so ignoring.")
            return

        if self.state == ConnectionState.ESTABLISHED:
            pt = QuicPacketType.ONE_RTT
        elif self.state == ConnectionState.LISTEN:
            pt = QuicPacketType.INITIAL
        else:
            raise RuntimeError(f"Cannot send CONNECTION_CLOSE from state: {self.state}")

        if payload is None:
            payload = [QuicFrame(QuicFrameType.TRANSPORT_CLOSE,
                                  content=ConnectionCloseFrame(QuicErrorCode.NO_ERROR,
                                                               reason=b'Idle timeout reached.'))]
        try:  # trigger on_tx() through memory channel:
            self.on_tx_send.send_nowait((pt, payload))
        except trio.WouldBlock:
            self._qlog.warn(f"*** WouldBlock (send_acks) triggered and prevented tx_send signal at {trio.current_time():.3f}",
                            stats=self.on_tx_send.statistics())
            pass  # ignore if buffer is full, which should not happen at infinite capacity

    async def do_handshake(self, hello_payload: bytes, remote_address: NetworkAddress) -> bool:
        """Try to perform the handshake.  Clients process the server's INITIAL response, creating a ONE_RTT with an
        ACK for server's INITIAL and moving into the ESTABLISHED state.  Servers process the client's INITIAL or
        ONE_RTT packet: in the first case responding with their own INITIAL packet including an ACK for the
        client's INITIAL and a CONFIG_ACK (with a possibly empty list of transport parameters).  In the second case,
        they process the client's ONE_RTT packet including the ACK for one of their ack-eliciting INITIAL packets,
        and then move into ESTABLISHED state.

        It's safe to call this multiple times – the server has to to process INITIAL and later ONE_RTT.  Once
        ESTABLISHED, this will be a no-op.

        :param hello_payload: this encodes the INITIAL QuicPacket; if we are the client side, then the destination
          connection ID from the payload should match our source CID.
          TODO: how to react if it doesn't match?
          If we are the server, then we are about to respond with our INITIAL QuicPacket.
        :param remote_address: Start tracking the network path using the remote address from where we received the
          hello packet.
        """
        if self.state == ConnectionState.ESTABLISHED:
            self._qlog.debug(f"do_handshake called when connection ESTABLISHED: ignoring")
            return True

        try:
            hello_packets = list(decode_udp_packet(hello_payload))
            assert len(hello_packets) >= 1  # TODO: If there are more QUIC packets, silently drop them?
            initial_pkt = hello_packets[0]
            assert initial_pkt.is_long_header, "client.do_handshake() expects long header packets only"
            assert initial_pkt.packet_type == QuicPacketType.INITIAL, "while client in handshake, only expect INITIAL"

            if self._is_client:
                assert initial_pkt.destination_cid == self.host_cid, "initial packet destination CID must be the same as my source CID"
                assert initial_pkt.version == QuicProtocolVersion.QUICLY, "initial packet version must be QUICLY"
            else:  # server-side of handshake
                if initial_pkt.version != QuicProtocolVersion.QUICLY:
                    # If a server refuses to accept a new connection, it SHOULD send an Initial packet containing
                    #  a CONNECTION_CLOSE frame with error code CONNECTION_REFUSED.
                    self.peer_cid.cid = initial_pkt.source_cid  # send_closing() will trigger _on_tx_loop()
                    refused_frame = ConnectionCloseFrame(QuicErrorCode.CONNECTION_REFUSED, reason=b'')
                    self.send_closing([QuicFrame(QuicFrameType.TRANSPORT_CLOSE, content=refused_frame)])
                    return False

            await self.on_rx([initial_pkt], remote_address)

        except AssertionError as ae:
            self._qlog.warn(f"do_handshake raised AssertionError: {ae}")
            # TODO: turn assertion errors into PROTOCOL_VIOLATION?
            return False
        self.remote_address = remote_address  # potentially overwrite client's initial target address
        return True

    def _handle_config(self, config_frame) -> bool:
        # TODO: what are the semantics of receiving peer parameters? Should they always override??
        peer_params = {PARAM_SCHEMA[tp.param_id][0]: tp.value for tp in config_frame.transport_parameters}
        return self.configuration.transport_parameters.update(peer_params)

    async def on_rx(self, quic_packets: List[QuicPacket], remote_addr: NetworkAddress = None) -> None:
        """
        Parse UDP payload into QUIC packets and frames to be handled.  Payload of any STREAM or DATAGRAM frames then
        gets forwarded to self._q.s.send(payload) for users of this QUIC connection to receive data.
        """
        self._qlog.info(f"Datagram received from {remote_addr}", pkts=quic_packets)

        if self.is_closing:
            self._qlog.warning(f"Connection to {remote_addr} already closing - dropping QUIC packets",
                               n_new_packets=len(quic_packets))
            return

        # TODO: check network path with `remote_addr`?

        for qp in quic_packets:
            # housekeeping with QUIC header info:
            if qp.packet_type != QuicPacketType.INITIAL or self._is_client:
                # check destination CID; skip for INITIAL at server (as it has not established CID):
                assert qp.destination_cid == self.host_cid  # TODO: once we migrate or have more CIDs...

            self._pn_space.note_received(qp.packet_number, now=trio.current_time())  # add PN to space

            if qp.packet_type == QuicPacketType.INITIAL:
                assert len(qp.payload) > 0
                if self.peer_cid.sequence_number is None:  # first INITIAL packet received
                    init_pkt = cast(LongHeaderPacket, qp)
                    self.peer_cid = QuicConnectionId(init_pkt.source_cid, 0, was_sent=True)

            # now handle frames (if payload present):
            ack_eliciting = False
            configuration_updated = False
            add_payload_to_ack = []  # only if ACK'ing immediately
            new_ack_encountered = False
            for qf in qp.payload:
                if qf.frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
                    ack_eliciting = True
                    self._pn_space.largest_ack_eliciting_pkt = qp.packet_number

                if qf.frame_type in [QuicFrameType.ACK, QuicFrameType.ACK_ECN]:
                    newly_established, newly_acked = self._loss.on_ack_received(
                        cast(ACKFrame, qf.content), qp.packet_type, trio.current_time())
                    if newly_established and self.state != ConnectionState.ESTABLISHED:
                        self._qlog.info(f"ESTABLISHED connection={hexdump(self.host_cid)}",
                                        recv_pkt_type=f"{qp.packet_type}")
                        self.state = ConnectionState.ESTABLISHED
                    new_ack_encountered |= newly_acked
                    continue

                if qf.frame_type in [QuicFrameType.TRANSPORT_CLOSE, QuicFrameType.APPLICATION_CLOSE]:
                    """The draining state is entered once an endpoint receives a CONNECTION_CLOSE frame, 
                    which indicates that its peer is closing or draining. While otherwise identical to the closing 
                    state, an endpoint in the draining state MUST NOT send any packets."""
                    self.enter_draining()

                if qf.frame_type in [QuicFrameType.CONFIG, QuicFrameType.CONFIG_ACK]:
                    configuration_updated |= self._handle_config(cast(ConfigFrame, qf.content))
                    if qf.frame_type == QuicFrameType.CONFIG:
                        # prepare CONFIG_ACK frame to go with ACK (to elicit ACK from client); even if ts == []
                        add_payload_to_ack.append(self._get_config_frame())
                    continue

                # TODO: when handling STREAM or DATAGRAM frames: forward their data payload to user of connection:
                # await connection._q.s.send(data_payload)

            if self._pn_space.ack_eliciting_in_flight > 0:
                if new_ack_encountered:  # only re-arm PTO if we saw a newly ack'ed packet number
                    self._rearm_pto()
            else:
                self.pto_timer.cancel()

            # restart idle timer to configured timeout but at least 3x the current PTO timeout
            self._idle_timer.set_timer_after(max(self.configuration.transport_parameters.idle_timeout_ms * K_MILLI_SECOND,
                                                 3 * self._loss.get_probe_timeout()))
            self._pn_space.last_successful_rx = trio.current_time()  # used to decide if we do the first TX of an
                                                                     # ack-liciting packet after last successful RX

            if ack_eliciting:
                max_ack_delay = self.configuration.transport_parameters.max_ack_delay_ms * K_MILLI_SECOND
                # An endpoint SHOULD generate and send an ACK frame without delay when it receives an ack-eliciting
                # packet either: (1) when the received packet has a packet number less than another ack-eliciting
                # packet that has been received, or (2) when the packet has a packet number larger than the
                # highest-numbered ack-eliciting packet that has been received and there are missing packets between
                # that packet and this packet. Similarly, packets marked with the ECN Congestion Experienced (CE)
                # codepoint in the IP header SHOULD be acknowledged immediately.
                # TODO: A receiver SHOULD send an ACK frame after receiving at least two ack-eliciting packets.
                if (
                        qp.packet_type == QuicPacketType.INITIAL or
                        qp.packet_number < self._pn_space.largest_ack_eliciting_pkt or
                        self._pn_space.largest_acked_packet < qp.packet_number - 2
                ):
                    max_ack_delay = 0
                if max_ack_delay > 0:
                    ack_deadline = trio.current_time() + max_ack_delay
                    if ack_deadline < self._ack_timer.deadline:  # an unarmed timer has deadline == math.inf
                        self._ack_timer.set_timer_at(ack_deadline)
                else:
                    self.send_acks(qp.packet_type, add_payload_to_ack)  # initiate on_tx() immediately!

            if self.state == ConnectionState.DRAINING:
                await self.aclose()

    async def send_all(self, data: bytes | bytearray | memoryview, contains_close: bool = False) -> None:
        """
        Schedules this data blob for sending at endpoint.
        """
        if self._closed:
            raise trio.ClosedResourceError("connection was already closed")
        # TODO: if QUIC Streams are also HalfClosable then do more state checking here...?
        await self.sending_ch.send((data, self.remote_address))
        if contains_close:
            # After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state.
            # Don't change current state if already closing.
            self.state = ConnectionState.CLOSING if not self.is_closing else self.state

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
