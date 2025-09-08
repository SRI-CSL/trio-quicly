#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
import math
from contextlib import contextmanager, suppress, asynccontextmanager
import errno
import logging
import trio
from types import TracebackType
from typing import *
import warnings

from .configuration import QuicConfiguration
from .connection import SimpleQuicConnection, ConnectionState, get_dcid_from_header
from .exceptions import QuicProtocolError
from .packet import MAX_UDP_PACKET_SIZE, decode_udp_packet
from .utils import _Queue, AddressFormat, PosArgsT
# from .stream import QuicStream, QuicBidiStream, QuicSendStream, QuicReceiveStream

logger = logging.getLogger("quicly")

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
            connection_id_length: int = 5,
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

        self.connection_id_length = connection_id_length
        self.incoming_packets_buffer = incoming_packets_buffer
        self._token = trio.lowlevel.current_trio_token()  # TODO: still needed?

        self._new_connections_q = _Queue[tuple[bytes, tuple[str, int], bytes]](float("inf"))
        self._send_q = _Queue[tuple[bytes, tuple[str, int]]](0)  # unbuffered sending Q for tuples (UDP payload, remote address)

        # We don't need to track handshaking vs non-handshake connections
        # separately. We only keep one connection per remote address.
        # {destination CID: QUIC connection}
        self._connections: dict[bytes, SimpleQuicConnection] = {}

        self._closed = False
        self._loops_spawned = False

    def start_endpoint(self, nursery: trio.Nursery) -> None:
        if not self._loops_spawned:
            nursery.start_soon(self._recv_loop)
            nursery.start_soon(self._send_loop)
            self._loops_spawned = True

    async def _send_loop(self) -> None:
        try:
            async with self._send_q.r:
                async for (udp_payload, remote_address) in self._send_q.r:
                    # modeled after `trio.SocketStream.send_all()` implementation
                    with _translate_socket_errors_to_stream_errors():
                        with memoryview(udp_payload) as data:
                            if not data:
                                if self.socket.fileno() == -1:
                                    raise trio.ClosedResourceError("socket was already closed")
                                await trio.lowlevel.checkpoint()
                                continue
                            total_sent = 0
                            while total_sent < len(data):
                                with data[total_sent:] as remaining:
                                    sent = await self.socket.sendto(remaining, remote_address)
                                total_sent += sent
        except trio.ClosedResourceError:
            # socket was closed
            return
        except OSError as exc:
            if exc.errno in (errno.EBADF, errno.ENOTSOCK):
                # socket was closed
                return
            else:  # pragma: no cover
                raise  # ??? shouldn't happen

    async def _recv_loop(self) -> None:
        try:
            while True:
                try:
                    udp_packet, address = await self.socket.recvfrom(MAX_UDP_PACKET_SIZE)
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
                await self._datagram_received(udp_packet, address)
        except trio.ClosedResourceError:
            # socket was closed
            return
        except OSError as exc:
            if exc.errno in (errno.EBADF, errno.ENOTSOCK):
                # socket was closed
                return
            else:  # pragma: no cover
                raise exc  # ??? shouldn't happen

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
        for stream in list(self._connections.values()):
            stream.close()
        self._new_connections_q.r.close()  # alerts anyone waiting on receive(), e.g., the server or client handshake
        self._send_q.r.close()

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

    async def _datagram_received(self, udp_payload: bytes, remote_address: Any) -> None:
        # TODO: handles anti-amplification, network path validation, and initial parsing before dispatching to the
        #   correct connection

        destination_cid = get_dcid_from_header(udp_payload, self.connection_id_length)
        if destination_cid is None:
            # drop (and log?) UDP packet as it wasn't formatted for QUIC
            return
        destination = self._connections.get(destination_cid, None)
        if destination is None:
            await self._new_connections_q.s.send((udp_payload, remote_address, destination_cid))
        else:
            await destination.on_rx(list(decode_udp_packet(udp_payload)), remote_address)
            # try:
            #     await destination.q.s.send(udp_payload)
            # except (trio.EndOfChannel, trio.BrokenResourceError):
            #     # TODO: logging of this event?
            #     del self._connections[destination_cid]

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

# async def quic_send_loop(
#         endpoint_ref: weakref.ReferenceType[QuicEndpoint],
#         udp_socket: trio.socket.SocketType,
# ) -> None:
#     try:
#         endpoint = endpoint_ref()
#         try:
#             if endpoint is None:
#                 return
#             async with endpoint.send_q.r:
#                 async for (udp_payload, remote_address) in endpoint.send_q.r:
#                     # modeled after `trio.SocketStream.send_all()` implementation
#                     with _translate_socket_errors_to_stream_errors():
#                         with memoryview(udp_payload) as data:
#                             if not data:
#                                 if udp_socket.fileno() == -1:
#                                     raise trio.ClosedResourceError("socket was already closed")
#                                 await trio.lowlevel.checkpoint()
#                                 continue
#                             total_sent = 0
#                             while total_sent < len(data):
#                                 with data[total_sent:] as remaining:
#                                     sent = await udp_socket.sendto(remaining, remote_address)
#                                 total_sent += sent
#         finally:
#             del endpoint
#     except trio.ClosedResourceError:
#         # socket was closed
#         return
#     except OSError as exc:
#         if exc.errno in (errno.EBADF, errno.ENOTSOCK):
#             # socket was closed
#             return
#         else:  # pragma: no cover
#             # ??? shouldn't happen
#             raise
#
# async def quic_receive_loop(
#     endpoint_ref: weakref.ReferenceType[QuicEndpoint],
#     udp_socket: trio.socket.SocketType,
# ) -> None:
#     try:
#         while True:
#             try:
#                 udp_packet, address = await udp_socket.recvfrom(MAX_UDP_PACKET_SIZE)
#                 print(f"\nrecvfrom: {udp_packet!r} from {address}")
#             except OSError as exc:
#                 if exc.errno == errno.ECONNRESET:
#                     # Windows only: "On a UDP-datagram socket [ECONNRESET]
#                     # indicates a previous send operation resulted in an ICMP Port
#                     # Unreachable message" -- https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
#                     #
#                     # This is totally useless -- there's nothing we can do with this
#                     # information. So we just ignore it and retry the recv.
#                     continue
#                 else:
#                     raise
#             endpoint = endpoint_ref()
#             try:
#                 if endpoint is None:
#                     return
#                 await endpoint.datagram_received(udp_packet, address)
#             finally:
#                 del endpoint
#     except trio.ClosedResourceError:
#         # socket was closed
#         return
#     except OSError as exc:
#         if exc.errno in (errno.EBADF, errno.ENOTSOCK):
#             # socket was closed
#             return
#         else:  # pragma: no cover
#             # ??? shouldn't happen
#             raise exc

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

        try:
            task_status.started()

            async def handle_connection(new_connection: SimpleQuicConnection) -> None:
                with new_connection:
                    await handler(new_connection, *args)
                # TODO: if we end up here, we should remove the connection from the endpoint's list!

            async with trio.open_nursery() as nursery:
                self.start_endpoint(nursery)
                if handler_nursery is None:
                    handler_nursery = nursery
                async for (payload, remote_address, destination_cid) in self._new_connections_q.r:
                    connection = self._connections.get(destination_cid, None)
                    if connection is None:
                        server_config = QuicConfiguration(is_client=False)
                        connection = SimpleQuicConnection(self._send_q.s.clone(),
                                                          remote_address,
                                                          self.connection_id_length,
                                                          self.incoming_packets_buffer,
                                                          server_config)
                        if await connection.do_handshake(payload, remote_address) and not connection.is_closed:
                            # handshake was successful
                            assert connection.state == ConnectionState.ESTABLISHED
                            assert connection.peer_cid.cid == destination_cid
                            self._connections[destination_cid] = connection
                            handler_nursery.start_soon(handle_connection, connection)
                        else:
                            # couldn't find recipient connection for this payload, so silently dropping
                            pass  # TODO: log it though?
                    else:
                        await connection.on_rx(list(decode_udp_packet(payload)), remote_address)
        finally:
            pass  # TODO: any other cleanup duties here?

@final
class QuicClient(QuicEndpoint):

    @asynccontextmanager
    async def connect(
        self,
        target_address: AddressFormat,  # could be 2-tuple (IPv4) or 4-tuple (IPv6)
        client_configuration: QuicConfiguration | None = None,
        connection_established_timeout: float = math.inf,  # TODO: establish default of 5-10s?
        initial_retransmit_timeout: float = 1.0,
    ) -> AsyncGenerator[SimpleQuicConnection, Any]:
        """Initiate an outgoing QUIC connection, which entails the handshake.  As QUIC 
        is based on UDP, we cannot reliably resolve the remote address until after receiving
        the first reply.

        If this endpoint already manages a (prior) connection to the same remote address,
        it will return the old connection after checking that it isn't closed.

        TODO: For simplicity, a client can only support 1 QUIC connection.  Therefore, if this
         method is called multiple times and to different destination addresses, it will
         silently fail...

        Args:
          target_address: The address to connect to. Usually a (host, port) tuple, like
            ``("127.0.0.1", 12345)``.  Note that unlike IPv4, in IPv6 the wildcard address
            does not resolve to localhost as a remote address.  Use the IPv6 wildcard address
            "::" only for servers that bind to them to all interfaces on localhost.
          client_configuration: The client configuration to use (or None for default values)
          connection_established_timeout: how many seconds before giving up on initial connection establishment.
          initial_retransmit_timeout: Since UDP is an unreliable protocol, it's
            possible that some of the packets we send during the handshake will get
            lost. To handle this, QUIC-LY uses a timer to automatically retransmit
            handshake packets that don't receive a response. This lets you set the
            timeout we use to detect packet loss. Ideally, it should be set to ~1.5
            times the round-trip time to your peer, but 1 second is a reasonable
            default. There's `some useful guidance here
            <https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-timer-values>`__.

            This is the *initial* timeout, because if packets keep being lost then we
            will automatically back off to longer values, to avoid overloading the
            network.

        Returns:
          SimpleQuicConnection

        """
        self._check_closed()

        async with trio.open_nursery() as nursery:
            self.start_endpoint(nursery)

            connection = SimpleQuicConnection(self._send_q.s.clone(),
                                              target_address,
                                              self.connection_id_length,
                                              self.incoming_packets_buffer,
                                              configuration=client_configuration)
            connection.start_background(nursery)

            with trio.move_on_after(connection_established_timeout) as cancel_scope:
                connection.state = ConnectionState.WAIT_FIRST
                while connection.state == ConnectionState.WAIT_FIRST and not connection.is_closed:
                    initial_pkt = connection.init_handshake()
                    await connection.on_tx(initial_pkt, initial_retransmit_timeout)  # this arms initial PTO timer
                    (payload, remote_address, destination_cid) = await self._new_connections_q.r.receive()
                    if await connection.do_handshake(payload, remote_address):
                        assert connection.peer_cid.cid == destination_cid
                        self._connections[destination_cid] = connection
                        break
                    # handshake unsuccessful:
                    # PTO timer will handle re-transmit, but we need to back-off with the PTO timer
                    initial_retransmit_timeout = 2*initial_retransmit_timeout
            if connection.is_closed or cancel_scope.cancelled_caught:
                raise QuicProtocolError("Could not establish QUIC connection")

            try:
                yield connection  # give caller control; loops continue running in the nursery
            finally:
                # on context exit: cancel everything cleanly
                nursery.cancel_scope.cancel()
                await connection.aclose()

