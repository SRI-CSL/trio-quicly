import secrets
import trio
from types import TracebackType
from typing import *

from .configuration import QuicConfiguration, SMALLEST_MAX_DATAGRAM_SIZE
from .packet import create_quic_packet, QuicPacketType, decode_quic_packet, LongHeaderPacket, \
    MAX_UDP_PACKET_SIZE, decode_udp_packet
from .utils import _Queue, AddressFormat

# @final
# TODO: first approximation is to simply match 1 QUIC connection without handshake to 1 QUIC bidi stream
class SimpleQuicConnection(trio.abc.Stream):
    def __init__(self,
                 sending_ch: trio.MemorySendChannel[tuple[bytes, tuple[str, int]]],
                 remote_address: Any,
                 incoming_packets_buffer: int,
                 configuration: QuicConfiguration) -> None:
        """
        Connection
        : A QUIC Connection is shared state between a client and a server. Connection IDs allow Connections to migrate
        to a new network path, both as a direct choice of an endpoint and when forced by a change in a middlebox.

        :param configuration:
        :param original_destination_connection_id:
        :param retry_source_connection_id:
        """

        assert sending_ch is not None, "Cannot create QUIC connection without sending channel"
        self.sending_ch = sending_ch

        assert configuration.max_datagram_size >= SMALLEST_MAX_DATAGRAM_SIZE, (
            "The smallest allowed maximum datagram size is "
            f"{SMALLEST_MAX_DATAGRAM_SIZE} bytes"
        )
        # if configuration.is_client:
        #     assert (
        #         original_destination_connection_id is None
        #     ), "Cannot set original_destination_connection_id for a client"
        #     assert (
        #         retry_source_connection_id is None
        #     ), "Cannot set retry_source_connection_id for a client"
        # else:
        #     assert (
        #         original_destination_connection_id is not None
        #     ), "original_destination_connection_id is required for a server"

        # configuration
        self._configuration = configuration
        self._is_client = configuration.is_client
        self.remote_address: AddressFormat = remote_address
        if self._is_client:
            assert self.remote_address is None
        else:
            assert self.remote_address is not None

        self._closed = False
        self._did_handshake = False
        self._handshake_lock = trio.Lock()  # guard handshake TODO: move to Stream?  No, as handshake is per connection!

        self.q = _Queue[bytes](incoming_packets_buffer)

        # # client- and server-specific configurations:
        # if self._is_client:
        #     self._original_destination_connection_id = original_destination_connection_id #TODO: self._peer_cid.cid
        # else:
        #     self._original_destination_connection_id = (
        #         original_destination_connection_id
        #     )

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
        # Will wake any tasks waiting on self.q.r.receive() with a ClosedResourceError
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
        # The client has not yet received a connection ID chosen by the server. Instead, it uses this field to
        # provide the 8 bytes of random data for deriving Initial encryption keys.
        # TODO: keep track in connection status:
        self.configuration.initial_random = secrets.token_bytes(8)
        self.configuration.source_cid = secrets.token_bytes(5)  # in QUIC Illustrated seems to be randomly chosen 5 bytes
        client_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                destination_cid=self.configuration.initial_random,
                                                source_cid=self.configuration.source_cid,
                                                packet_number=0,  # TODO: keep track in connection status
                                                payload=bytes.fromhex("ff"))  # TODO: TLS ClientHello etc. payload
        # Any datagram sent by the client that contains an Initial packet must be padded to a length of
        #  1200 bytes. This library does it by appending nul bytes to the datagram.
        return client_initial_pkt.encode_all_bytes().ljust(SMALLEST_MAX_DATAGRAM_SIZE, b'\x00')

    async def do_handshake(self, hello_payload: bytes, *, initial_retransmit_timeout: float = 1.0,
                           stream_payload: bytes = None) -> None:
        """Perform the handshake.

        It's safe to call this multiple times, or call it simultaneously from multiple
        tasks – the first call will perform the handshake, and the rest will be no-ops.

        Args:

          hello_payload (bytes): this encodes the INITIAL QuicPacket; if we are the
            client side, then the initial key material etc. should already be generated
            and match the payload.  TODO: how to react if it doesn't match?
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
          stream_payload: Optional stream payload to be sent with last handshake packet.
            Only useful from client side as it will be ignored from the server side.

        """
        async with (self._handshake_lock):
            if self._did_handshake:
                return

            # TODO: perform actual QUIC handshake (implementing TLS 1.3 etc.)
            if self._is_client:
                # # The client has not yet received a connection ID chosen by the server. Instead, it uses this field to
                # # provide the 8 bytes of random data for deriving Initial encryption keys.
                # initial_random = secrets.token_bytes(8)
                # source_cid = secrets.token_bytes(5)  # in QUIC Illustrated seems to be randomly chosen 5 bytes
                # client_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                #                                         destination_cid=initial_random,
                #                                         source_cid=source_cid,
                #                                         packet_number=0,
                #                                         payload=bytes.fromhex("ff")) # TODO: TLS ClientHello etc. payload
                # # Any datagram sent by the client that contains an Initial packet must be padded to a length of
                # #  1200 bytes. This library does it by appending nul bytes to the datagram.
                # await self.send_all(client_initial_pkt.encode_all_bytes().ljust(SMALLEST_MAX_DATAGRAM_SIZE, b'\x00'))
                #
                # # awaiting first response from new connections queue:
                # (payload, remote_address) = await self.endpoint.new_connections_q.r.receive()
                # self.remote_address = remote_address

                hello_packets = list(decode_udp_packet(hello_payload))
                assert len(hello_packets) == 2

                server_initial_pkt = hello_packets[0]
                assert isinstance(server_initial_pkt, LongHeaderPacket)
                assert server_initial_pkt.packet_type == QuicPacketType.INITIAL
                assert server_initial_pkt.packet_number == 0
                assert server_initial_pkt.destination_cid == self.configuration.source_cid  # TODO: turn into status
                # TODO: signal endpoint that this packet validated?

                server_handshake_pkt = hello_packets[1]
                assert isinstance(server_handshake_pkt, LongHeaderPacket)
                assert server_handshake_pkt.packet_type == QuicPacketType.HANDSHAKE
                assert server_handshake_pkt.packet_number == 0

                udp_payload = await self.q.r.receive()
                server_handshake_pkt = next(decode_udp_packet(udp_payload))
                assert isinstance(server_handshake_pkt, LongHeaderPacket)
                assert server_handshake_pkt.packet_type == QuicPacketType.HANDSHAKE
                assert server_handshake_pkt.packet_number == 1

                # UDP Datagram 4 = ACKs: INITIAL, HANDSHAKE, and PADDING
                client_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                        destination_cid=server_handshake_pkt.source_cid,
                                                        source_cid=server_handshake_pkt.destination_cid,
                                                        packet_number=1,
                                                        payload=bytes.fromhex("aa")).encode_all_bytes()  # TODO: ACK Frame
                client_handshake_pkt = create_quic_packet(QuicPacketType.HANDSHAKE,
                                                          destination_cid=server_handshake_pkt.source_cid,
                                                          source_cid=server_handshake_pkt.destination_cid,
                                                          packet_number=0,
                                                          payload=bytes.fromhex("aa")).encode_all_bytes()  # TODO: ACK Frame
                # Any datagram sent by the client that contains an Initial packet must be padded to a length of
                #  1200 bytes. This library does it by appending nul bytes to the datagram.
                await self.send_all(client_initial_pkt +
                                    client_handshake_pkt.ljust(SMALLEST_MAX_DATAGRAM_SIZE - len(client_initial_pkt), b'\x00'))

                # TODO: UDP Datagram 5 = Client handshake finished, "ping"
                #  The client sends a "Handshake" packet, containing the client's "Handshake Finished" TLS record,
                #  completing the handshake process.
                client_handshake_pkt = create_quic_packet(QuicPacketType.HANDSHAKE,
                                                          destination_cid=server_handshake_pkt.source_cid,
                                                          source_cid=server_handshake_pkt.destination_cid,
                                                          packet_number=1,
                                                          payload=bytes.fromhex("bb")).encode_all_bytes()  # TODO: ACK Frame
                if stream_payload:
                    client_packet = create_quic_packet(QuicPacketType.ONE_RTT,
                                                       destination_cid=server_handshake_pkt.source_cid,
                                                       spin_bit=False, key_phase=False,
                                                       packet_number=0,
                                                       payload=stream_payload).encode_all_bytes()  # TODO: STREAM frames
                    await self.send_all(client_handshake_pkt + client_packet)
                else:
                    await self.send_all(client_handshake_pkt)

            else:  # server-side of handshake
                # parse hello_payload as client initial packet:
                client_initial_pkt = next(decode_udp_packet(hello_payload))
                assert len(hello_payload) == SMALLEST_MAX_DATAGRAM_SIZE  # should be padded
                assert isinstance(client_initial_pkt, LongHeaderPacket)
                assert client_initial_pkt.packet_type == QuicPacketType.INITIAL
                # TODO: if error then close this connection? self.close()

                source_cid = secrets.token_bytes(5)  # in QUIC Illustrated seems to be randomly chosen 5 bytes
                server_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                                                        destination_cid=client_initial_pkt.source_cid,  # repeated back
                                                        source_cid=source_cid,
                                                        packet_number=0,
                                                        payload=bytes.fromhex("ee")) # TODO: TLS ClientHello etc. payload
                # TODO: The server follows up with a "Handshake" packet. This packet contains TLS 1.3 handshake
                #  records from the server.
                server_handshake_pkt = create_quic_packet(QuicPacketType.HANDSHAKE,
                                                        destination_cid=client_initial_pkt.source_cid,  # repeated back
                                                        source_cid=source_cid,
                                                        packet_number=0,
                                                        payload=bytes.fromhex("ff")) # TODO: TLS ClientHello etc. payload
                # INITIAL and first HANDSHAKE combined into 1 UDP Datagram:
                await self.send_all(server_initial_pkt.encode_all_bytes() + server_handshake_pkt.encode_all_bytes())

                # TODO: The server continues with another "Handshake" packet. This packet contains the rest of the
                #  server's TLS 1.3 handshake records.
                #  NOTE: the second HANDSHAKE packet has number 1.  It should be sent in a 2nd UDP Datagram
                server_handshake_pkt = create_quic_packet(QuicPacketType.HANDSHAKE,
                                                        destination_cid=client_initial_pkt.source_cid,  # repeated back
                                                        source_cid=source_cid,
                                                        packet_number=1,
                                                        payload=bytes.fromhex("aa bb")) # TODO: TLS ClientHello etc. payload
                await self.send_all(server_handshake_pkt.encode_all_bytes())

                # TODO: obtain 3-4 packets (combined into 2 UDP Datagrams):
                udp_payload = await self.q.r.receive()  # INITIAL, 1 and HANDSHAKE, 0
                packets = list(decode_udp_packet(udp_payload))
                assert len(packets) == 2
                udp_payload = await self.q.r.receive()  # HANDSHAKE, 1 and [optional] APP, 0
                packets = list(decode_udp_packet(udp_payload))
                assert len(packets) <= 2
                if len(packets) == 2:
                    one_rtt_pkt = packets[1]
                    stream_payload = one_rtt_pkt.payload  # TODO: forward payload from 2nd packet...

            self._did_handshake = True

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
