#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from enum import Enum, auto
from dataclasses import dataclass
import secrets
import trio
from types import TracebackType
from typing import *

from .configuration import QuicConfiguration, SMALLEST_MAX_DATAGRAM_SIZE, PARAM_SCHEMA
from .frame import decode_var_length_int, QuicFrame, QuicFrameType, ConfigFrame, TransportParameter
from .packet import create_quic_packet, QuicPacketType, LongHeaderPacket, \
    MAX_UDP_PACKET_SIZE, decode_udp_packet, QuicProtocolVersion
from .utils import _Queue, AddressFormat

def get_dcid_from_header(data: bytes, cid_length: int) -> Optional[bytes]:
    """
    Try to parse CID from header (scid from INITIAL, dcid from 1-RTT)
    :param data: payload bytes of a QUIC Packet
    :return: connection ID, if parsing succeeded
    """
    if len(data) < 2:
        return None
    if data[0] & 0x80:  # long header
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
                 remote_address: Any,
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
        # if configuration.is_client:
        #     assert original_destination_connection_id is None, (
        #         "Cannot set original_destination_connection_id for a client"
        #     )
        # #     assert (
        # #         retry_source_connection_id is None
        # #     ), "Cannot set retry_source_connection_id for a client"
        # else:
        #     assert original_destination_connection_id is not None, (
        #         "original_destination_connection_id is required for a server"
        #     )
        self._configuration = configuration
        self._is_client = configuration.is_client

        self.remote_address: AddressFormat = remote_address
        if self._is_client:
            assert self.remote_address is None
        else:
            assert self.remote_address is not None

        # state management:
        self._closed = False
        self._did_handshake = False  # after successful handshake, connection is ESTABLISHED
        self._handshake_lock = trio.Lock()  # guard handshake TODO: move to Stream?  No, as handshake is per connection!
        self.state = ConnectionState.START if self._is_client else ConnectionState.LISTEN
        self.draining_until = None
        self._closing_frame = None
        self._saw_ack_eliciting = False  # touched during closing to decide if/when to re-send close

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
        self._peer_cid = QuicConnectionId(
            cid=secrets.token_bytes(connection_id_length),
            sequence_number=None
        )
        self._peer_cid_available: List[QuicConnectionId] = []
        self._peer_cid_sequence_numbers: Set[int] = {0}
        self._peer_retire_prior_to = 0
        self._packet_number = 0

        self.q = _Queue[bytes](incoming_packets_buffer)

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def is_closed(self) -> bool:
        return self._closed

    # @property
    # def original_destination_connection_id(self) -> bytes:
    #     return self._original_destination_connection_id

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
        self.q.r.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
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

    def init_handshake(self) -> bytes:
        ts = [TransportParameter(*tp) for tp in self.configuration.transport_parameters.as_list(exclude_defaults=True)]
        client_config_frame = QuicFrame(QuicFrameType.CONFIG,
                                        content=ConfigFrame(ts))
        client_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                destination_cid=b'',  # don't need initial random bits in QUIC-LY!
                                                source_cid=self.host_cid,
                                                packet_number=self._packet_number,  # TODO: increment!
                                                payload=[client_config_frame])
        # Any datagram sent by the client that contains an Initial packet must be padded to a length of
        # INITIAL_PADDING_TARGET bytes. This library does it by appending nul bytes to the datagram.
        return client_initial_pkt.encode_all_bytes().ljust(
            self.configuration.transport_parameters.initial_padding_target, b'\x00')

    async def do_handshake(self, hello_payload: bytes, *, initial_retransmit_timeout: float = 1.0,
                           data_payload: bytes = None) -> bool:
        """Perform the handshake.

        It's safe to call this multiple times, or call it simultaneously from multiple
        tasks – the first call will perform the handshake, and the rest will be no-ops.

        Args:

          hello_payload (bytes): this encodes the INITIAL QuicPacket; if we are the
            client side, then the initial connection ID should match the payload.
            TODO: how to react if it doesn't match?
            If we are the server, then are about to respond with our INITIAL QuicPacket.
          initial_retransmit_timeout (float): Since UDP is an unreliable protocol, it's
            possible that some of the packets we send during the handshake will get
            lost. To handle this, QUIC uses a timer to automatically retransmit
            handshake packets that don't receive a response. This lets you set the
            timeout we use to detect packet loss. Ideally, it should be set to ~1.5
            times the round-trip time to your peer, but 1 second is a reasonable
            default. There's `some useful guidance here
            <https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-timer-values>`__.

            This is the *initial* timeout, because if packets keep being lost then Trio
            will automatically back off to longer values, to avoid overloading the
            network.
          data_payload: Optional stream or datagram payload to be sent with initial packet.
            Only useful from client side as it will be ignored from the server side.
            TODO: what does this mean for QUIC-LY? Can't we already initiate with STREAM (or DATAGRAM) payload?

        """
        async with (self._handshake_lock):  # TODO: check await's under this for blocking this top-level with()
            if self._did_handshake:
                return True

            # TODO: turn assertion errors into PROTOCOL_VIOLATION, QLog, and False return values...
            if self._is_client:
                hello_packets = list(decode_udp_packet(hello_payload))
                assert len(hello_packets) == 1  # TODO: Could there be more QUIC packets?  I think so...

                server_initial_pkt = hello_packets[0]
                assert isinstance(server_initial_pkt, LongHeaderPacket)
                assert server_initial_pkt.packet_type == QuicPacketType.INITIAL
                assert server_initial_pkt.packet_number == 0
                assert server_initial_pkt.destination_cid == self.host_cid  # TODO: turn into status?
                self.current_destination_cid = server_initial_pkt.source_cid
                assert len(server_initial_pkt.payload) > 0

                # find last CONFIG_ACK frame in payload:
                last_cfg_ack = next((f for f in reversed(server_initial_pkt.payload)
                                     if f.frame_type == QuicFrameType.CONFIG_ACK), None)
                assert last_cfg_ack is not None
                assert isinstance(last_cfg_ack.content, ConfigFrame)
                server_params = {PARAM_SCHEMA[tp.param_id][0]: tp.value
                                 for tp in last_cfg_ack.content.transport_parameters}
                self.configuration.transport_parameters.update(server_params)

                # TODO: parse out ACK frames?
                # TODO: signal endpoint that this packet validated??

                if data_payload:  # any STREAM or DATAGRAM payload to immediately send?
                    # TODO: client_stream_frame = QuicFrame(QuicFrameType.STREAM_BASE,
                    #                                 content=StreamFrame(stream_id=0, data=stream_payload))
                    client_packet = create_quic_packet(QuicPacketType.ONE_RTT,
                                                       destination_cid=server_initial_pkt.source_cid,
                                                       spin_bit=False, key_phase=False,
                                                       packet_number=0,
                                                       payload=[QuicFrame(QuicFrameType.PADDING)])
                    await self.send_all(client_packet.encode_all_bytes())

            else:  # server-side of handshake
                # parse hello_payload as client initial packet:
                client_initial_pkt = next(decode_udp_packet(hello_payload))
                # NOTE: A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that
                # is smaller than the smallest allowed maximum datagram size of 1200 bytes.
                # TODO: A server MAY also
                #  immediately close the connection by sending a CONNECTION_CLOSE frame with an error code of
                #  PROTOCOL_VIOLATION
                if len(hello_payload) < SMALLEST_MAX_DATAGRAM_SIZE:
                    # TODO: logging, sending CONN_CLOSE?
                    return False
                assert isinstance(client_initial_pkt, LongHeaderPacket)
                assert client_initial_pkt.packet_type == QuicPacketType.INITIAL
                if client_initial_pkt.version != QuicProtocolVersion.QUICLY:
                    # TODO: logging, error handling
                    return False
                # TODO: keep track of packet number...
                self.current_destination_cid = client_initial_pkt.source_cid
                assert len(client_initial_pkt.payload) > 0

                # find last CONFIG frame in payload:
                last_cfg = next((f for f in reversed(client_initial_pkt.payload)
                                 if f.frame_type == QuicFrameType.CONFIG), None)
                assert last_cfg is not None
                assert isinstance(last_cfg.content, ConfigFrame)
                # TODO: what are the semantics of receiving client parameters? Should they always override servers'?
                client_params = {PARAM_SCHEMA[tp.param_id][0]: tp.value
                                 for tp in last_cfg.content.transport_parameters}
                self.configuration.transport_parameters.update(client_params)

                # TODO: send CONFIG_ACK in response
                self.configuration.source_cid = secrets.token_bytes(5)  # in QUIC Illustrated seems to be randomly chosen 5 bytes
                ts = [TransportParameter(*tp) for tp in
                      self.configuration.transport_parameters.as_list(exclude_defaults=True)]
                server_config_frame = QuicFrame(QuicFrameType.CONFIG_ACK,
                                                content=ConfigFrame(ts))
                server_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                        destination_cid=client_initial_pkt.source_cid,  # repeated back
                                                        source_cid=self.configuration.source_cid,
                                                        packet_number=0,  # TODO: keep track of this!
                                                        payload=[server_config_frame])
                # TODO: padding this one as well?
                await self.send_all(server_initial_pkt.encode_all_bytes().ljust(
                    self.configuration.transport_parameters.initial_padding_target, b'\x00'))

            self.state = ConnectionState.ESTABLISHED
            self._did_handshake = True
            return True

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        """Sends the given data through the stream, blocking if necessary.

        Args:
          data (bytes, bytearray, or memoryview): The data to send.

        Raises:
          trio.BusyResourceError: if another task is already executing a
              :meth:`send_all`, :meth:`wait_send_all_might_not_block`, or
              :meth:`HalfCloseableStream.send_eof` on this stream.
          trio.BrokenResourceError: if something has gone wrong, and the stream
              is broken.
          trio.ClosedResourceError: if you previously closed this stream
              object, or if another task closes this stream object while
              :meth:`send_all` is running.

        Most low-level operations in Trio provide a guarantee: if they raise
        :exc:`trio.Cancelled`, this means that they had no effect, so the
        system remains in a known state. This is **not true** for
        :meth:`send_all`. If this operation raises :exc:`trio.Cancelled` (or
        any other exception for that matter), then it may have sent some, all,
        or none of the requested data, and there is no way to know which.
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
            packet = await self.q.r.receive()
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
