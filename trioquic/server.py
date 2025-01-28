import errno
import trio
from typing import *

from trioquic.configuration import QuicConfiguration
from trioquic.connection import SimpleQuicConnection, QuicListener


async def open_quic_listeners(
    port: int,
    *,
    host: str | bytes | None = None,
) -> list[QuicListener]:
    """Create :class:`QuicListener` objects to listen for QUIC connections.

    Args:

      port (int): The port to listen on.

          If you use 0 as your port, then the kernel will automatically pick
          an arbitrary open port. But be careful: if you use this feature when
          binding to multiple IP addresses, then each IP address will get its
          own random port, and the returned listeners will probably be
          listening on different ports. In particular, this will happen if you
          use ``host=None`` – which is the default – because in this case
          :func:`open_tcp_listeners` will bind to both the IPv4 wildcard
          address (``0.0.0.0``) and also the IPv6 wildcard address (``::``).

      host (str, bytes, or None): The local interface to bind to. This is
          passed to :func:`~socket.getaddrinfo` with the ``AI_PASSIVE`` flag
          set.

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
      list of :class:`QuicListener`

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
                await sock.bind(sockaddr)
                listeners.append(QuicListener(sock))
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

async def serve_quic(
    connection_handler: Callable[[SimpleQuicConnection], Awaitable[object]],
    port: int,
    *,
    host: str | bytes = None,
    handler_nursery: Optional[trio.Nursery] = None,
    task_status: trio.TaskStatus[list[QuicListener]] = trio.TASK_STATUS_IGNORED,
    configuration: Optional[QuicConfiguration] = None,
    # session_ticket_fetcher: Optional[SessionTicketFetcher] = None,
    # session_ticket_handler: Optional[SessionTicketHandler] = None,
    # retry: bool = False,
    # stream_handler: Optional[QuicStreamHandler] = None,
) -> None:
    """
    Listen for incoming connections, and spawn a handler for each using an
    internal nursery.

    Similar to `~trio.serve_tcp`, this function never returns until cancelled or
    all handlers have exited.

    Usage commonly looks like::

        async def handler(quic_connection):
            ...

        async with trio.open_nursery() as nursery:
            await nursery.start(trioquic.trio.serve_quick, ssl_context, handler)
            # ... do other things here ...

    Args:
      # ssl_context (OpenSSL.SSL.Context): The PyOpenSSL context object to use for
        incoming connections.
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

    # modeled after `trio.serve_tcp`:
    listeners = await open_quic_listeners(port, host=host)
    await trio.serve_listeners(
        connection_handler,
        listeners,
        handler_nursery=handler_nursery,
        task_status=task_status,
    )
