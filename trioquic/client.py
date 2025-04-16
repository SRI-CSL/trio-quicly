import trio
from typing import *

from .configuration import QuicConfiguration
from .connection import SimpleQuicConnection
from .endpoint import QuicClient

# @contextmanager
# def close_all() -> Generator[set[trio.socket.SocketType], None, None]:
#     sockets_to_close: set[trio.socket.SocketType] = set()
#     try:
#         yield sockets_to_close
#     finally:
#         errs = []
#         for sock in sockets_to_close:
#             try:
#                 sock.close()
#             except BaseException as exc:
#                 errs.append(exc)
#         if len(errs) == 1:
#             raise errs[0]
#         elif errs:
#             raise BaseExceptionGroup("", errs)

def format_host_port(host: str | bytes, port: int) -> str:
    host = host.decode("ascii") if isinstance(host, bytes) else host
    if ":" in host:
        return f"[{host}]:{port}"
    else:
        return f"{host}:{port}"

async def open_quic_connection(
        host: str | bytes,
        port: int,
        *,
        configuration: Optional[QuicConfiguration] = None,
) -> SimpleQuicConnection:
    """
    Connect to the given host and port over QUIC.

    This will open an IPv4 or IPv6 datagram socket to the specified QUIC server.

    TODO: Before implementing QuicStreams, test with connection == bidi stream, so connecting also
      starts a receive loop?
    """

    client_configuration = QuicConfiguration(
        is_client=True,
    ) if configuration is None else configuration
    assert (client_configuration.is_client is True), "client configuration must not also be server"

    # To keep our public API surface smaller, rule out some cases that
    # getaddrinfo will accept in some circumstances, but that act weird or
    # have non-portable behavior or are just plain not useful.
    if not isinstance(host, (str, bytes)):
        raise ValueError(f"host must be str or bytes, not {host!r}")
    if not isinstance(port, int):
        raise TypeError(f"port must be int, not {port!r}")

    targets = await trio.socket.getaddrinfo(
        host,
        port,
        type=trio.socket.SOCK_DGRAM,
        proto=trio.socket.IPPROTO_UDP)

    # I don't think this can actually happen -- if there are no results,
    # getaddrinfo should have raised OSError instead of returning an empty
    # list. But let's be paranoid and handle it anyway:
    if not targets:
        raise OSError(f"no results found for hostname lookup: {format_host_port(host, port)}")

    # Like `aioquic` for clients, use only first address
    # Then, we don't need to do Happy Eyeballs (RFC 6555) either!
    family, stype, proto, _, winning_address = targets[0]
    client_socket = trio.socket.socket(family, stype, proto)
    # TODO: `aioquic` also  make it IPv6 if IPv4 returned...
    # if family == trio.socket.AF_INET:
    #      winning_address = ("::ffff:" + winning_address[0], winning_address[1], 0, 0)
    # # explicitly enable IPv4/IPv6 dual stack
    # client_socket = trio.socket.socket(trio.socket.AF_INET6, stype, proto)
    # client_socket.setsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY, 0)

    client = QuicClient(client_socket)
    return await client.connect(winning_address, client_configuration)
