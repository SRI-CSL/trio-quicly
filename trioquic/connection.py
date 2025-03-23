import contextlib
import warnings
from contextlib import contextmanager
import errno
import logging
import socket as psocket  # Python socket
import trio
from types import TracebackType
from typing import *
import weakref

from .configuration import QuicConfiguration, SMALLEST_MAX_DATAGRAM_SIZE
from .packet import MAX_UDP_PACKET_SIZE, create_quic_packet, QuicPacketType

# from .stream import QuicStream, QuicBidiStream, QuicSendStream, QuicReceiveStream

logger = logging.getLogger("trioquic")

AddressFormat: TypeAlias = tuple[str, int]
PosArgsT = TypeVarTuple("PosArgsT")
_T = TypeVar("_T")

class _Queue(Generic[_T]):
    def __init__(self, incoming_packets_buffer: int | float) -> None:  # noqa: PYI041
        self.s, self.r = trio.open_memory_channel[_T](incoming_packets_buffer)

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

class QuicEndpoint:
    """A QUIC endpoint.  Should be instantiated as either a server or a client.

    A single UDP socket can serve arbitrarily many QUIC connections simultaneously.
    A `QuicEndpoint` server object holds the UDP socket and manages these connections,
    which are represented as `QuicConnection` objects.  A `QuicEndpoint` client object
    instead connects only once to a remote QUIC server and uses the same UDP socket
    for sending and receiving data while that one connection exists.

    QUIC Connections and ultimately the created Streams do the receiving and sending
    of data (in bytes) over Trio memory channels with their attached Endpoint, which
    manages the guarded UDP socket and translates stream send/receive to socket send
    and receive operations.

    Args:
      socket: (trio.socket.SocketType): A ``SOCK_DGRAM`` socket.
      incoming_packets_buffer (int):
      TODO: Each `DTLSChannel` using this socket has its own
        buffer that holds incoming packets until you call `~DTLSChannel.receive` to read
        them. This lets you adjust the size of this buffer. `~DTLSChannel.statistics`
        lets you check if the buffer has overflowed.

    .. attribute:: socket
                   incoming_packets_buffer

       Both constructor arguments are also exposed as attributes, in case you need to
       access them later.

    """

    def __init__(
            self,
            socket: trio.socket.SocketType,
            *,
            incoming_packets_buffer: int = 10,
    ):
        # for __del__, in case the next line raises
        self._initialized: bool = False
        if socket.type != trio.socket.SOCK_DGRAM:
            raise ValueError("QUIC requires a SOCK_DGRAM socket")
        if not isinstance(socket, trio.socket.SocketType):
            raise TypeError("QUIC endpoints require a Trio socket object")
        self._initialized = True
        self.socket: trio.socket.SocketType = socket

        self.incoming_packets_buffer = incoming_packets_buffer
        self._token = trio.lowlevel.current_trio_token()
        self.new_connections_q = _Queue[tuple[bytes, tuple[str, int]]](float("inf"))

        # We don't need to track handshaking vs non-handshake connections
        # separately. We only keep one connection per remote address.
        # {remote address: QUIC connection}
        self.connections: dict[AddressFormat, SimpleQuicConnection] = {}

        self._send_lock = trio.Lock()
        self._closed = False
        self._receive_loop_spawned = False

    def ensure_receive_loop(self) -> None:
        # We have to spawn this lazily, because on Windows it will immediately error out
        # if the socket isn't already bound -- which for clients might not happen until
        # after we send our first packet.
        if not self._receive_loop_spawned:
            trio.lowlevel.spawn_system_task(
                quic_receive_loop,
                weakref.ref(self),
                self.socket,
            )
            self._receive_loop_spawned = True

    def __del__(self) -> None:
        # Do nothing if this object was never fully constructed
        if not self._initialized:
            return
        # Close the socket in Trio context (if our Trio context still exists), so that
        # the background task gets notified about the closure and can exit.
        if not self._closed:
            with contextlib.suppress(RuntimeError):
                self._token.run_sync_soon(self.close)
            # Do this last, because it might raise an exception
            warnings.warn(
                f"unclosed QUIC endpoint {self!r}",
                ResourceWarning,
                source=self,
                stacklevel=1,
            )

    def close(self) -> None:
        """Close this socket, and all associated QUIC connections.
        This object can also be used as a context manager.
        """
        self._closed = True
        self.socket.close()
        for stream in list(self.connections.values()):
            stream.close()
        self.new_connections_q.r.close()  # alerts anyone waiting on receive(), e.g., the server or client handshake

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return self.close()

    def _check_closed(self) -> None:
        if self._closed:
            raise trio.ClosedResourceError

    async def _send_to(self, data: bytes | bytearray | memoryview, remote_address: AddressFormat) -> None:
        # modeled after `trio.SocketStream.send_all()` implementation
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
                            sent = await self.socket.sendto(remaining, remote_address)
                        total_sent += sent

    async def _wait_socket_writable(self) -> None:
        async with self._send_lock:
            if self.socket.fileno() == -1:
                raise trio.ClosedResourceError
            with _translate_socket_errors_to_stream_errors():
                await self.socket.wait_writable()

# @final
# TODO: first approximation is to simply match 1 QUIC connection without handshake to 1 QUIC bidi stream
class SimpleQuicConnection(trio.abc.Stream):
    def __init__(
            self,
            endpoint: QuicEndpoint,
            remote_address: Any,
            configuration: QuicConfiguration,
            # original_destination_connection_id: Optional[bytes] = None,
            # retry_source_connection_id: Optional[bytes] = None
    ) -> None:
        """
        Connection
        : A QUIC Connection is shared state between a client and a server. Connection IDs allow Connections to migrate
        to a new network path, both as a direct choice of an endpoint and when forced by a change in a middlebox.

        :param configuration:
        :param original_destination_connection_id:
        :param retry_source_connection_id:
        """

        assert endpoint is not None, "Cannot create QUIC connection without endpoint"
        self.endpoint = endpoint

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
        self._closed = False
        self._did_handshake = False
        self._handshake_lock = trio.Lock()  # guard handshake TODO: move to Stream?  No, as handshake is per connection!

        self.q = _Queue[bytes](endpoint.incoming_packets_buffer)

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
        if self.endpoint.connections.get(self.remote_address) is self:
            del self.endpoint.connections[self.remote_address]
        # Will wake any tasks waiting on self._q.receive() with a ClosedResourceError
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

    async def do_handshake(self, hello_payload: bytes = None, *, initial_retransmit_timeout: float = 1.0) -> None:
        """Perform the handshake.

        It's safe to call this multiple times, or call it simultaneously from multiple
        tasks – the first call will perform the handshake, and the rest will be no-ops.

        Args:

          hello_payload (bytes): if given and not None, then perform the server-side of
            the handshake. Otherwise, initiate the handshake from the client-side.
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

        """
        async with self._handshake_lock:
            if self._did_handshake:
                return
            self.endpoint.ensure_receive_loop()

            # TODO: perform actual QUIC handshake (implementing TLS 1.3 etc.)
            if hello_payload is None:
                # client-side of handshake: create initial packet
                # dest_cid =
                # source_cid =
                # client_initial_pkt = create_quic_packet(QuicPacketType.INITIAL,
                #                                         dest_cid,
                #                                         source_cid=source_cid,
                #                                         packet_number=packet_number,
                #                                         payload=bytes.fromhex("ff")) # TODO: TLS ClientHello etc.
                await self.send_all(b'ClientHello')
                (payload, remote_address) = await self.endpoint.new_connections_q.r.receive()
                assert payload == b'ServerHello'
                self.remote_address = remote_address
            else:
                # server-side of handshake
                assert hello_payload == b'ClientHello'
                await self.send_all(b'ServerHello')

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
        await self.endpoint._send_to(data, self.remote_address)

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
        await self.endpoint._wait_socket_writable()

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

async def quic_receive_loop(
    endpoint_ref: weakref.ReferenceType[QuicEndpoint],
    udp_socket: trio.socket.SocketType,
) -> None:
    try:
        while True:
            try:
                udp_packet, address = await udp_socket.recvfrom(MAX_UDP_PACKET_SIZE)
                print(f"\nrecvfrom: {udp_packet!r} from {address}")
            except OSError as exc:
                if exc.errno == errno.ECONNRESET:
                    # Windows only: "On a UDP-datagram socket [ECONNRESET]
                    # indicates a previous send operation resulted in an ICMP Port
                    # Unreachable message" -- https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
                    #
                    # This is totally useless -- there's nothing we can do with this
                    # information. So we just ignore it and retry the recv.
                    continue
                else:
                    raise
            endpoint = endpoint_ref()
            try:
                if endpoint is None:
                    return
                destination = endpoint.connections.get(address, None)
                if destination is None:
                    await endpoint.new_connections_q.s.send((udp_packet, address))
                else:
                    await destination.q.s.send(udp_packet)
            finally:
                del endpoint
    except trio.ClosedResourceError:
        # socket was closed
        return
    except OSError as exc:
        if exc.errno in (errno.EBADF, errno.ENOTSOCK):
            # socket was closed
            return
        else:  # pragma: no cover
            # ??? shouldn't happen
            raise

@final
class QuicServer(QuicEndpoint):

    def __init__(self, bound_socket: trio.socket.SocketType, address: tuple[str | bytes | None, int]) -> None:
        QuicEndpoint.__init__(self, bound_socket)
        try:
            self.socket.getsockname()
        except OSError:
            raise RuntimeError("UDP socket must be operational bound before it can serve") from None
        self.address = address

        # self._listening_context: SSL.Context | None = None
        # self._listening_key: bytes | None = None

    async def serve(
        self,
        handler: Callable[[SimpleQuicConnection, Unpack[PosArgsT]], Awaitable[object]],
        handler_nursery: trio.Nursery,
        *args: Unpack[PosArgsT],
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        """Listen for incoming connections, and spawn a handler for each using an
        internal nursery.

        Similar to `~trio.serve_tcp`, this function never returns until cancelled, or
        the `QuicEndpoint` is closed and all handlers have exited.

        Usage commonly looks like::

            async def handler(quic_connection):
                ...

            async with trio.open_nursery() as nursery:
                await nursery.start(quic_server.serve, handler)
                # ... do other things here ...

        Args:
          :param handler: The handler function that will be invoked for each new,
            incoming connection.
          :param handler_nursery: The nursery to use for handling each connection;
            create an internal one if None is given
          *args: Additional arguments to pass to the handler function.
          :param task_status:

        """
        self._check_closed()
        self.ensure_receive_loop()

        try:
            task_status.started()

            async def handler_wrapper(stream: SimpleQuicConnection) -> None:
                with stream:
                    await handler(stream, *args)

            async with trio.open_nursery() as nursery:
                if handler_nursery is None:
                    handler_nursery = nursery
                async for (payload, remote_address) in self.new_connections_q.r:
                    new_connection = self.connections.get(remote_address, None)
                    if new_connection is None:
                        new_connection = SimpleQuicConnection(self,
                                                              remote_address,
                                                              configuration=QuicConfiguration(is_client=False))
                        await new_connection.do_handshake(payload)
                        assert new_connection.remote_address == remote_address  # TODO: is this true?
                        self.connections[new_connection.remote_address] = new_connection
                        handler_nursery.start_soon(handler_wrapper, new_connection)
                    else:
                        # TODO: should this actually happen?
                        await new_connection.q.s.send(payload)
        finally:
            pass  # TODO: any other cleanup duties here?

# @final
# class QuicListener(trio.abc.Listener[SimpleQuicConnection],QuicEndpoint):
#     """A :class:`~trio.abc.Listener` that uses a bound UDP socket to accept
#     incoming connections as :class:`SimpleQuicConnection` objects.  It is
#     a QUIC endpoint server object.
#
#     Args:
#       bound_socket: The Trio socket object to wrap. Must have type ``SOCK_DGRAM``,
#           and be bound.
#
#     Note that the :class:`QuicListener` "takes ownership" of the given
#     socket; closing the :class:`QuicListener` will also close the socket.
#
#     .. attribute:: socket
#
#        The Trio socket object that this stream wraps.
#
#     """
#     def __init__(self, bound_socket: trio.socket.SocketType) -> None:
#         QuicEndpoint.__init__(self, bound_socket)
#         # TODO: how to check that UDP socket is bound?
#         # try:
#         #     listening = socket.getsockopt(tsocket.SOL_SOCKET, tsocket.SO_ACCEPTCONN)
#         # except OSError:
#         #     # SO_ACCEPTCONN fails on macOS; we just have to trust the user.
#         #     pass
#         # else:
#         #     if not listening:
#         #         raise ValueError("QuicListener requires a bound socket")
#         self.accept_send_ch, self._accept_recv_ch = trio.open_memory_channel(0)
#
#     async def aclose(self) -> None:
#         """Close this listener and its underlying socket."""
#         print(f"QuicListener.aclose() called")
#         self.socket.close()
#         await trio.lowlevel.checkpoint()
#
#     async def accept(self) -> SimpleQuicConnection:
#         self._ensure_receive_loop()
#         with self._accept_recv_ch.clone() as new_client:
#             client_address = await new_client.receive()
#             connection = SimpleQuicConnection(self, client_address, configuration=QuicConfiguration(is_client=False))
#             self.connections[client_address] = connection
#             print(f"new connection from {client_address} accepted!")
#             return connection

@final
class QuicClient(QuicEndpoint):

    async def connect(
        self,
        target_address: AddressFormat,  # could be 2-tuple (IPv4) or 4-tuple (IPv6)
        client_configuration: Optional[QuicConfiguration] = None,
    ) -> SimpleQuicConnection:
        """Initiate an outgoing QUIC connection, which entails the handshake.  As QUIC 
        is based on UDP, we cannot reliably resolve the remote address until after receiving
        the first reply.

        If this endpoint already manages a (prior) connection to the same remote address,
        it will return the old connection after checking that it isn't closed.

        Args:
          target_address: The address to connect to. Usually a (host, port) tuple, like
            ``("127.0.0.1", 12345)``.  Note that unlike IPv4, in IPv6 the wildcard address
            does not resolve to localhost as a remote address.  Use the IPv6 wildcard address
            "::" only for servers that bind to them to all interfaces on localhost.
          client_configuration: The client configuration to use (or None for default values)

        Returns:
          SimpleQuicConnection

        """
        self._check_closed()

        connection = self.connections.get(target_address, None)
        if connection is not None:
            # TODO: should there be anything else done here when re-using an existing connection?
            assert connection.is_closed is False, "connect() should never return a closed connection"
            return connection

        connection = SimpleQuicConnection(self, target_address, configuration=client_configuration)
        await connection.do_handshake()
        self.connections[connection.remote_address] = connection
        return connection
