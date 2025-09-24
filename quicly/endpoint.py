#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
from contextlib import contextmanager, suppress, asynccontextmanager
import errno
import trio
from types import TracebackType
from typing import *
import warnings

from .configuration import QuicConfiguration
from .connection import SimpleQuicConnection, ConnectionState, get_cid_from_header
from .exceptions import QuicProtocolError, QuicErrorCode
from .frame import ConnectionCloseFrame, QuicFrame, QuicFrameType
from .logger import QlogMemoryCollector, init_logging, make_qlog
from .packet import MAX_UDP_PACKET_SIZE, decode_udp_packet
from .utils import _Queue, AddressFormat, PosArgsT, hexdump, K_MILLI_SECOND
# from .stream import QuicStream, QuicBidiStream, QuicSendStream, QuicReceiveStream

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

        # tracking ESTABLISHED connections:
        self._connections: dict[bytes, SimpleQuicConnection] = {}  # {destination CID: QUIC connection}

        self._closed = False
        self._loops_spawned = False

        self._qlog, self._mem_qlog = init_logging()
        # NOTE:  1.3. Events not belonging to a single connection
        #
        # A single qlog event trace is typically associated with a single QUIC connection. However, for several types
        # of events (for example, a Section 5.7 event with trigger value of connection_unknown), it can be impossible
        # to tie them to a specific QUIC connection, especially on the server. There are various ways to handle these
        # events, each making certain tradeoffs between file size overhead, flexibility, ease of use, or ease of
        # implementation. Log them in a separate endpoint-wide trace (or use a special group_id value) not associated
        # with a single connection.

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
                    self._qlog.debug(f"recvfrom: {len(udp_packet)} bytes from {address}")
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
        self.dump_qlog()

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

        destination_cid = get_cid_from_header(udp_payload, self.connection_id_length)
        if destination_cid is None:
            self._qlog.info(f"UDP datagram from {remote_address} does not contain CID: drop", size=len(udp_payload))
            return
        destination = self._connections.get(destination_cid, None)
        if destination is None:
            # connection for destination not yet established:
            await self._new_connections_q.s.send((udp_payload, remote_address, destination_cid))
        else:
            self._qlog.debug(f"UDP datagram from known CID={hexdump(destination_cid)}", size=len(udp_payload))
            await destination.on_rx(list(decode_udp_packet(udp_payload, destination_cid)), remote_address)

    def dump_qlog(self):
        if isinstance(self._mem_qlog, QlogMemoryCollector):
            # TODO: make these persist as files...
            current_qlog = self._mem_qlog.get_qlogs()
            self._qlog.info("Closing endpoint; here is a dump of the QLOGs in memory:\n" +
                            "\n".join(f'odcid = {trace} : [\n  {",\n  ".join(str(e) for e in events)}\n]'
                                      for trace, events in current_qlog.items()) + "\n")
            # written = self._mem_qlog.dump_ndjson_per_trace(Path.cwd(), "server_{odcid}.qlog")
            # self._qlog.info(f"Written {len(written)} files", written=written)


@final
class QuicServer(QuicEndpoint):

    def __init__(self, bound_socket: trio.socket.SocketType, address: tuple[str | bytes | None, int]) -> None:
        QuicEndpoint.__init__(self, bound_socket)
        try:
            self.socket.getsockname()
        except OSError:
            raise RuntimeError("UDP socket must be operational bound before it can serve") from None
        self.address = address
        # tracking new connections until they become ESTABLISHED:
        self._new_connections: dict[bytes, SimpleQuicConnection] = {}  # {remote source CID: QUIC connection}
        self._qlog = make_qlog("server", "connectivity")

    def close(self) -> None:
        # TODO: will this be invoked from QuicServer(Endpoint).aclose()?
        for stream in list(self._new_connections.values()):  # if any still pending
            stream.close()
        super().close()

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
                    connection = self._new_connections.get(destination_cid, None)
                    if connection is None:
                        self._qlog.debug(f"~~~ Starting NEW connection CID={hexdump(destination_cid)}")
                        server_config = QuicConfiguration(is_client=False)
                        connection = SimpleQuicConnection(self._send_q.s.clone(),
                                                          remote_address,
                                                          self.connection_id_length,
                                                          self.incoming_packets_buffer,
                                                          server_config)
                        self._new_connections[destination_cid] = connection
                        connection.start_background(nursery)
                    else:
                        self._qlog.debug(f"~~~ Serving existing NEW connection CID={hexdump(destination_cid)}")

                    if await connection.do_handshake(payload, remote_address):
                        assert connection.peer_cid.cid == destination_cid
                        if connection.host_cid not in self._connections.keys():
                            # first successful handshake: note connection for future packet delivery
                            self._connections[connection.host_cid] = connection
                            handler_nursery.start_soon(handle_connection, connection)
        finally:
            pass  # any server-specific cleanup?

@final
class QuicClient(QuicEndpoint):

    def __init__(self, bound_socket: trio.socket.SocketType) -> None:
        QuicEndpoint.__init__(self, bound_socket)
        self._qlog = make_qlog("client", "connectivity")

    @asynccontextmanager
    async def connect(
        self,
        target_address: AddressFormat,  # could be 2-tuple (IPv4) or 4-tuple (IPv6)
        client_configuration: QuicConfiguration | None = None,
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
        Returns:
          SimpleQuicConnection
        """
        self._check_closed()

        async with trio.open_nursery() as nursery:
            self.start_endpoint(nursery)
            self._qlog.info(f"Trying to connect to {target_address}")

            connection = SimpleQuicConnection(self._send_q.s.clone(),
                                              target_address,
                                              self.connection_id_length,
                                              self.incoming_packets_buffer,
                                              configuration=client_configuration)
            connection.start_background(nursery)

            with trio.move_on_after(connection.configuration.transport_parameters.idle_timeout_ms * K_MILLI_SECOND) \
                    as cancel_scope:
                initial_pkt = connection.init_handshake()
                await connection.on_tx(initial_pkt)  # this arms PTO timer to re-transmit INITIAL if needed
                async for (payload, remote_address, destination_cid) in self._new_connections_q.r:
                    if await connection.do_handshake(payload, remote_address):
                        assert connection.peer_cid.cid == destination_cid
                    # else: handshake unsuccessful: PTO timer will handle re-transmit of INITIAL (as probe)
                    if connection.state == ConnectionState.ESTABLISHED:
                        self._qlog.info(f"Connected to {remote_address}")
                        self._connections[connection.host_cid] = connection  # clients only use 1 connection
                        # now datagrams will be delivered directly to this connection!
                        break

            try:
                if connection.is_closed or cancel_scope.cancelled_caught:
                    self._qlog.warning(f"Could not establish QUIC connection to {target_address} - exiting.")
                    connection.peer_cid.cid = connection.host_cid  # we haven't established a valid peer address yet
                    timeout_frame = ConnectionCloseFrame(QuicErrorCode.NO_ERROR,
                                                         reason=b'Idle timeout during handshake reached.')
                    connection.send_closing([QuicFrame(QuicFrameType.TRANSPORT_CLOSE, content=timeout_frame)])
                    # raise QuicProtocolError("Could not establish QUIC connection")
                else:
                    yield connection  # give caller control; loops continue running in the nursery
            finally:
                # on context exit: cancel everything cleanly
                nursery.cancel_scope.cancel()
                await connection.aclose()
                self.dump_qlog()