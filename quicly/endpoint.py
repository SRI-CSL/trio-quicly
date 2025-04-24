#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from contextlib import contextmanager, suppress
import errno
import logging
import trio
from types import TracebackType
from typing import *
import warnings
import weakref

from .configuration import QuicConfiguration
from .connection import SimpleQuicConnection
from .exceptions import QuicProtocolError
from .packet import MAX_UDP_PACKET_SIZE
from .utils import _Queue, AddressFormat, PosArgsT

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
        self.send_q = _Queue[tuple[bytes, tuple[str, int]]](0)  # unbuffered sending Q for tuples (UDP payload, remote address)

        # We don't need to track handshaking vs non-handshake connections
        # separately. We only keep one connection per remote address.
        # {remote address: QUIC connection}
        self.connections: dict[AddressFormat, SimpleQuicConnection] = {}

        self._send_lock = trio.Lock()
        self._closed = False
        self._loops_spawned = False

    def _ensure_receive_and_send_loops(self) -> None:
        # We have to spawn this lazily, because on Windows it will immediately error out
        # if the socket isn't already bound -- which for clients might not happen until
        # after we send our first packet.
        if not self._loops_spawned:
            trio.lowlevel.spawn_system_task(
                quic_receive_loop,
                weakref.ref(self),
                self.socket,
            )
            trio.lowlevel.spawn_system_task(
                quic_send_loop,
                weakref.ref(self),
                self.socket,
            )
            self._loops_spawned = True

    def __del__(self) -> None:
        # Do nothing if this object was never fully constructed
        if not self._initialized:
            return
        # Close the socket in Trio context (if our Trio context still exists), so that
        # the background task gets notified about the closure and can exit.
        if not self._closed:
            with suppress(RuntimeError):
                self._token.run_sync_soon(self.close, )
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
        self.send_q.r.close()

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

    # async def _send_to(self, data: bytes | bytearray | memoryview, remote_address: AddressFormat) -> None:
    #     # modeled after `trio.SocketStream.send_all()` implementation
    #     async with self._send_lock:
    #         with _translate_socket_errors_to_stream_errors():
    #             with memoryview(data) as data:
    #                 if not data:
    #                     if self.socket.fileno() == -1:
    #                         raise trio.ClosedResourceError("socket was already closed")
    #                     await trio.lowlevel.checkpoint()
    #                     return
    #                 total_sent = 0
    #                 while total_sent < len(data):
    #                     with data[total_sent:] as remaining:
    #                         sent = await self.socket.sendto(remaining, remote_address)
    #                     total_sent += sent
    #
    # async def _wait_socket_writable(self) -> None:
    #     async with self._send_lock:
    #         if self.socket.fileno() == -1:
    #             raise trio.ClosedResourceError
    #         with _translate_socket_errors_to_stream_errors():
    #             await self.socket.wait_writable()

async def quic_send_loop(
        endpoint_ref: weakref.ReferenceType[QuicEndpoint],
        udp_socket: trio.socket.SocketType,
) -> None:
    try:
        endpoint = endpoint_ref()
        try:
            if endpoint is None:
                return
            async with endpoint.send_q.r:
                async for (udp_payload, remote_address) in endpoint.send_q.r:
                    # modeled after `trio.SocketStream.send_all()` implementation
                    with _translate_socket_errors_to_stream_errors():
                        with memoryview(udp_payload) as data:
                            if not data:
                                if udp_socket.fileno() == -1:
                                    raise trio.ClosedResourceError("socket was already closed")
                                await trio.lowlevel.checkpoint()
                                continue
                            total_sent = 0
                            while total_sent < len(data):
                                with data[total_sent:] as remaining:
                                    sent = await udp_socket.sendto(remaining, remote_address)
                                total_sent += sent
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
                    try:
                        await destination.q.s.send(udp_packet)
                    except (trio.EndOfChannel, trio.BrokenResourceError):
                        # TODO: logging of this event?
                        del endpoint.connections[address]
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
            raise exc

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
        self._ensure_receive_and_send_loops()

        try:
            task_status.started()

            async def establish_and_handle(new_connection: SimpleQuicConnection, initial_payload: bytes) -> None:
                if await new_connection.do_handshake(initial_payload) and not new_connection.is_closed:
                    # handshake was successful
                    with new_connection:
                        await handler(new_connection, *args)
                # TODO: if we end up here, we should remove the connection from the endpoint's list!

            async with trio.open_nursery() as nursery:
                if handler_nursery is None:
                    handler_nursery = nursery
                async for (payload, remote_address) in self.new_connections_q.r:
                    connection = self.connections.get(remote_address, None)
                    if connection is None:
                        connection = SimpleQuicConnection(self.send_q.s.clone(),
                                                          remote_address,
                                                          self.incoming_packets_buffer,
                                                          configuration=QuicConfiguration(is_client=False))
                        self.connections[connection.remote_address] = connection
                        handler_nursery.start_soon(establish_and_handle, connection, payload)
                    else:
                        await connection.q.s.send(payload)
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

        TODO: For simplicity, a client can only support 1 QUIC connection.  Therefore, if this
         method is called multiple times and to different destination addresses, it will
         silently fail... (Linda: or should it not?)

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
        self._ensure_receive_and_send_loops()

        connection = self.connections.get(target_address, None)
        if connection is not None:
            # TODO: should there be anything else done here when re-using an existing connection?
            assert connection.is_closed is False, "connect() should never return a closed connection"
            return connection

        connection = SimpleQuicConnection(self.send_q.s.clone(),
                                          None,
                                          self.incoming_packets_buffer,
                                          configuration=client_configuration)
        encoded_initial_pkt = connection.init_handshake()  # creates crypto material etc.
        await self.send_q.s.send((encoded_initial_pkt, target_address))
        (payload, remote_address) = await self.new_connections_q.r.receive()  # TODO: what about timeouts?
        connection.remote_address = remote_address
        self.connections[connection.remote_address] = connection
        await connection.do_handshake(payload) # TODO: check that return is True, payload is INITIAL, 0 from server etc.
        if connection.is_closed:
            raise QuicProtocolError("Could not establish QUIC connection")
        return connection
