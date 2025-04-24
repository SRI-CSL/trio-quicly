#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

import errno
import trio
from typing import *

from .configuration import QuicConfiguration
from .connection import SimpleQuicConnection
from .endpoint import QuicServer, PosArgsT

StreamT = TypeVar("StreamT", bound=trio.abc.AsyncResource)
Handler = Callable[[StreamT], Awaitable[object]]

async def open_quic_servers(
    port: int,
    *,
    host: str | bytes | None = None,
) -> list[QuicServer]:
    """Create :class:`QuicServer` objects to listen for QUIC connections.

    Args:

      port (int): The port to listen on.

          If you use 0 as your port, then the kernel will automatically pick
          an arbitrary open port. But be careful: if you use this feature when
          binding to multiple IP addresses, then each IP address will get its
          own random port, and the returned listeners will probably be
          listening on different ports. Note, unlike
          :func:`trio.open_tcp_listeners`, this will not happen if you
          use ``host=None`` – which is the default; if ``host=None`` we prefer
          binding to the IPv6 wildcard address (``::``) and enabling dual-stack
          support so that IPv4 clients are also supported.

      host (str, bytes, or None): The local interface to bind to. This is
          passed to :func:`~socket.getaddrinfo`.

          If you want to bind to the wildcard address on both IPv4 and IPv6,
          in order to accept connections on all available interfaces, then
          pass ``None``. This is the default.

          If you have a specific interface you want to bind to, pass its IP
          address or hostname here. If a hostname resolves to multiple IP
          addresses, this function will open one listener on each of them.

          If you want to use only IPv4, or only IPv6, but want to accept on
          all interfaces, pass the family-specific wildcard address:
          ``"0.0.0.0"`` for IPv4-only and ``"::"`` for IPv6-only.

    Returns:
      list of :class:`QuicServer`

    Raises:
      :class:`TypeError` if invalid arguments.

    """
    # getaddrinfo sometimes allows port=None, sometimes not (depending on
    # whether host=None). And on some systems it treats "" as 0, others it
    # doesn't:
    #   http://klickverbot.at/blog/2012/01/getaddrinfo-edge-case-behavior-on-windows-linux-and-osx/
    if not isinstance(port, int):
        raise TypeError(f"port must be an int not {port!r}")

    addresses = await trio.socket.getaddrinfo(
        host,
        port,
        type=trio.socket.SOCK_DGRAM,
        proto=trio.socket.IPPROTO_UDP,
    )

    listeners = []
    unsupported_address_families = []
    try:
        if host is None:
            # just open one listener on the wildcard address;
            # if AF_INET6 in possible addresses then enable dual-stack:
            unique_families = {tup[0] for tup in addresses}
            if trio.socket.AF_INET6 in unique_families:
                family = trio.socket.AF_INET6
            elif len(unique_families):
                family = unique_families.pop()
            else:
                raise OSError(errno.EAFNOSUPPORT,
                              "This system does not support required socket")

            server_socket = None
            try:
                server_socket = trio.socket.socket(family,
                                                   type=trio.socket.SOCK_DGRAM,
                                                   proto=trio.socket.IPPROTO_UDP)
                if family == trio.socket.AF_INET6:
                    # explicitly enable IPv4/IPv6 dual stack
                    server_socket.setsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY, 0)
                await server_socket.bind((host, port))
                listeners.append(QuicServer(server_socket, (host, port)))
            except OSError as ex:
                if ex.errno == errno.EAFNOSUPPORT:
                    # If a system only supports IPv4 but getaddrinfo
                    # returns both an IPv4 and an IPv6 address then
                    # we might be out of luck.  One can force then
                    # IPv4-only with "0.0.0.0" as the host address.
                    unsupported_address_families.append(ex)
                else:
                    if server_socket is not None:
                        server_socket.close()
                    raise
        else:
            # go through all addresses and try to open one listener for each
            for family, stype, proto, _, sockaddr in addresses:
                assert ( stype == trio.socket.SOCK_DGRAM ), "only working with UDP sockets"
                try:
                    sock = trio.socket.socket(family, stype, proto)
                except OSError as ex:
                    if ex.errno == errno.EAFNOSUPPORT:
                        # If a system only supports IPv4, or only IPv6, it
                        # is still likely that getaddrinfo will return
                        # both an IPv4 and an IPv6 address. As long as at
                        # least one of the returned addresses can be
                        # turned into a socket, we won't complain about a
                        # failure to create the other.
                        unsupported_address_families.append(ex)
                        continue
                    else:
                        raise
                try:
                    if family == trio.socket.AF_INET6:
                        if host == "::":
                            # only support IPv6
                            sock.setsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY, 1)
                        else:
                            # explicitly enable IPv4/IPv6 dual stack
                            sock.setsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY, 0)
                    await sock.bind(sockaddr)
                    listeners.append(QuicServer(sock, sockaddr))
                except:
                    sock.close()
                    raise
    except:
        for listener in listeners:
            listener.socket.close()
        raise

    if unsupported_address_families and not listeners:
        msg = (
            "This system doesn't support any of the kinds of "
            "socket that that address could use"
        )
        raise OSError(errno.EAFNOSUPPORT, msg) from ExceptionGroup(
            msg,
            unsupported_address_families,
        )

    return listeners

async def _run_handler(stream: StreamT, handler: Handler[StreamT]) -> None:
    try:
        await handler(stream)
    finally:
        await trio.aclose_forcefully(stream)

async def serve_quic(
    connection_handler: Callable[[SimpleQuicConnection, Unpack[PosArgsT]], Awaitable[object]],
    port: int,
    *args,
    host: str | bytes = None,
    handler_nursery: trio.Nursery | None = None,
    task_status: trio.TaskStatus[list[QuicServer]] = trio.TASK_STATUS_IGNORED,
    configuration: QuicConfiguration | None = None,
    # session_ticket_fetcher: Optional[SessionTicketFetcher] = None,
    # session_ticket_handler: Optional[SessionTicketHandler] = None,
    # retry: bool = False,
) -> None:
    """
    Start at least one (more if given host resolves to multiple addresses) QUIC
    server.  Similar to `~trio.serve_tcp`, this function never returns until
    cancelled or all QUIC servers have exited.

    Args:
      connection_handler: The handler function that will be invoked for each incoming
        connection.
      port (int): The port to listen on. Use 0 to let the kernel pick an open port.
      *args: Additional arguments to pass to the handler function.

      host (str | bytes | None): The host interface to listen on;
        use ``None`` to bind to the localhost (TODO: or wildcard?) address.
    """

    server_configuration = QuicConfiguration(
        is_client=False
    ) if configuration is None else configuration
    assert (server_configuration.is_client is False), "server configuration must not also be client"

    servers = await open_quic_servers(port, host=host)
    # modeled after `trio.serve_listeners`:
    async with trio.open_nursery() as nursery:
        for server in servers:
            nursery.start_soon(server.serve, connection_handler, handler_nursery, *args)
        # The listeners are already queueing connections when we're called,
        # but we wait until the end to call started() just in case we get an
        # error or whatever.
        task_status.started(servers)

    raise AssertionError(
        "QuicServer.serve should never complete",
    )