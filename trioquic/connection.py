from contextlib import contextmanager
import errno
import trio
import logging
from typing import *

from .configuration import QuicConfiguration, SMALLEST_MAX_DATAGRAM_SIZE
from .packet import MAX_UDP_PACKET_SIZE

# from .stream import QuicStream, QuicBidiStream, QuicSendStream, QuicReceiveStream

logger = logging.getLogger("trioquic")

@contextmanager
def _translate_socket_errors_to_stream_errors() -> Generator[None, None, None]:
    try:
        yield
    except OSError as exc:
        if exc.errno in {
            errno.EBADF, # Unix
            errno.ENOTSOCK, # Windows
        }:
            raise trio.ClosedResourceError("this socket was already closed") from None
        else:
            raise trio.BrokenResourceError(f"socket connection broken: {exc}") from exc

# @final
# TODO: first approximation is to simply match 1 QUIC connection without handshake to 1 QUIC bidi stream
class SimpleQuicConnection(trio.abc.Stream):

    def __init__(
        self,
        udp_socket: trio.socket.SocketType,
        remote_address: Any,
        *,
        configuration: QuicConfiguration,
        original_destination_connection_id: Optional[bytes] = None,
        retry_source_connection_id: Optional[bytes] = None,
    ) -> None:
        """
        Connection
        : A QUIC Connection is shared state between a client and a server. Connection IDs allow Connections to migrate
        to a new network path, both as a direct choice of an endpoint and when forced by a change in a middlebox.

        :param configuration:
        :param original_destination_connection_id:
        :param retry_source_connection_id:
        """

        assert udp_socket is not None, "Cannot create QUIC connection without UDP socket"
        # TODO: check remote address?
        assert configuration.max_datagram_size >= SMALLEST_MAX_DATAGRAM_SIZE, (
            "The smallest allowed maximum datagram size is "
            f"{SMALLEST_MAX_DATAGRAM_SIZE} bytes"
        )
        if configuration.is_client:
            assert (
                original_destination_connection_id is None
            ), "Cannot set original_destination_connection_id for a client"
            assert (
                retry_source_connection_id is None
            ), "Cannot set retry_source_connection_id for a client"
        else:
            assert (
                original_destination_connection_id is not None
            ), "original_destination_connection_id is required for a server"

        # configuration
        self._configuration = configuration
        self._is_client = configuration.is_client

        self._socket = udp_socket
        self._address: Tuple[str | bytes, int] | None = remote_address
        self._send_lock = trio.Lock()  # guard sending calls to socket TODO: move to Stream?

        if self._is_client:
            self._original_destination_connection_id = original_destination_connection_id #TODO: self._peer_cid.cid
        else:
            self._original_destination_connection_id = (
                original_destination_connection_id
            )

        # self._quick_streams = {}

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def original_destination_connection_id(self) -> bytes:
        return self._original_destination_connection_id

    @property
    def socket(self) -> trio.socket.SocketType:
        return self._socket

    # async def connect(self, host: str | bytes, port: int) -> None:
    #     """
    #     Initiate the QUIC (TLS) handshake.
    #
    #     This method can only be called for clients and a single time.  When returning without error and no
    #     cancellation attempt has been made, the connection is in state CONNECTED.
    #
    #     :param host: The IP address of the remote peer.
    #     :param port: The port number of the remote peer.
    #     """
    #     assert (
    #         self._is_client and not self._connected
    #     ), "connect() can only be called for clients and a single time"
    #
    #     self._address = (host, port)
    #     await self._socket.connect(self._address)  # TODO: Can be IPv4 or IPv6?
    #
    #     # TODO: now perform handshake...
    #     self._connected = True

    # TODO: move to QuicStream...

    async def aclose(self) -> None:
        """Close this strean and its underlying socket."""
        self._socket.close()
        await trio.lowlevel.checkpoint()

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        # TODO: if QUIC Streams are also HalfClosable then do more state checking here...
        # TODO: see trio.SocketStream.send_all() implementation!
        async with self._send_lock:
            with _translate_socket_errors_to_stream_errors():
                with memoryview(data) as data:
                    if not data:
                        if self.socket.fileno() == -1:
                            raise trio.ClosedResourceError("socket was already closed")
                        await trio.lowlevel.checkpoint()
                        return
                    total_sent = 0
                    while total_sent < len(data):
                        with data[total_sent:] as remaining:
                            sent = await self.socket.send(remaining)
                        total_sent += sent

    async def wait_send_all_might_not_block(self) -> None:
        async with self._send_lock:
            if self.socket.fileno() == -1:
                raise trio.ClosedResourceError
            with _translate_socket_errors_to_stream_errors():
                await self.socket.wait_writable()

    async def receive_some(self, max_bytes: int | None = None) -> bytes | bytearray:
        if max_bytes is None:
            max_bytes = MAX_UDP_PACKET_SIZE
        if max_bytes < 1:
            raise ValueError("max_bytes must be >= 1")
        with _translate_socket_errors_to_stream_errors():
            return await self.socket.recv(max_bytes)

    def datagram_received(self, payload: bytes) -> None:
        print(f"received data {payload!r}")

    # def create_stream(self, bidirectional: bool = True) -> QuicStream:
    #     return QuicBidiStream() if bidirectional else QuicSendStream()
    #     # # TODO: while testing with TCP:
    #     # assert (self._is_client and self._connect_called)
    #     # return await trio.open_tcp_stream(self.host, self.port)
    #
    # def accept_stream(self, bidirectional: bool = True) -> QuicStream:
    #     return QuicBidiStream() if bidirectional else QuicReceiveStream()

@final
class QuicListener(trio.abc.Listener[SimpleQuicConnection]):
    """A :class:`~trio.abc.Listener` that uses a bound UDP socket to accept
    incoming connections as :class:`SimpleQuicConnection` objects.

    Args:
      socket: The Trio socket object to wrap. Must have type ``SOCK_DGRAM``,
          and be bound.

    Note that the :class:`QuicListener` "takes ownership" of the given
    socket; closing the :class:`QuicListener` will also close the socket.

    .. attribute:: socket

       The Trio socket object that this stream wraps.

    """

    def __init__(self, socket: trio.socket.SocketType) -> None:
        if not isinstance(socket, trio.socket.SocketType):
            raise TypeError("QuicListener requires a Trio socket object")
        if socket.type != trio.socket.SOCK_DGRAM:
            raise ValueError("QuicListener requires a SOCK_DGRAM socket")
        # TODO: how to check that UDP socket is bound?
        # try:
        #     listening = socket.getsockopt(tsocket.SOL_SOCKET, tsocket.SO_ACCEPTCONN)
        # except OSError:
        #     # SO_ACCEPTCONN fails on macOS; we just have to trust the user.
        #     pass
        # else:
        #     if not listening:
        #         raise ValueError("QuicListener requires a bound socket")
        self.socket = socket
        self.connections: dict[Any, SimpleQuicConnection] = {}

    async def aclose(self) -> None:
        """Close this listener and its underlying socket."""
        self.socket.close()
        await trio.lowlevel.checkpoint()

    async def accept(self) -> SimpleQuicConnection:
        try:
            udp_payload, client_address = await self.socket.recvfrom(MAX_UDP_PACKET_SIZE)
            connection = SimpleQuicConnection(
                self.socket,
                client_address,
                configuration=QuicConfiguration()
            )
            connection.datagram_received(udp_payload)
            return connection
        except OSError as exc:
            if exc.errno == errno.ECONNRESET:
                # Windows only: "On a UDP-datagram socket [ECONNRESET]
                # indicates a previous send operation resulted in an ICMP Port
                # Unreachable message" -- https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
                #
                # This is totally useless -- there's nothing we can do with this
                # information. So we just ignore it and retry the recv.
                pass
            else:
                raise

        # except trio.ClosedResourceError:
        #     # socket was closed
        #     return None
        # except OSError as exc:
        #     if exc.errno in (errno.EBADF, errno.ENOTSOCK):
        #         # socket was closed
        #         return
        #     else:  # pragma: no cover
        #         # ??? shouldn't happen
        #         raise

        # connection = connections.get(address, QuicConnection(configuration=server_configuration))
        # connection.datagram_received(udp_payload)
