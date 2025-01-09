from contextlib import contextmanager
import socket
import trio
from typing import *

from trioquic.configuration import QuicConfiguration
from trioquic.connection import SimpleQuicConnection


@contextmanager
def close_all() -> Generator[set[trio.socket.SocketType], None, None]:
    sockets_to_close: set[trio.socket.SocketType] = set()
    try:
        yield sockets_to_close
    finally:
        errs = []
        for sock in sockets_to_close:
            try:
                sock.close()
            except BaseException as exc:
                errs.append(exc)
        if len(errs) == 1:
            raise errs[0]
        elif errs:
            raise BaseExceptionGroup("", errs)

def format_host_port(host: str | bytes, port: int) -> str:
    host = host.decode("ascii") if isinstance(host, bytes) else host
    if ":" in host:
        return f"[{host}]:{port}"
    else:
        return f"{host}:{port}"

def reorder_for_rfc_6555_section_5_4(  # type: ignore[misc]
    targets: list[tuple[socket.AddressFamily, socket.SocketKind, int, str, Any]],
) -> None:
    # RFC 6555 section 5.4 says that if getaddrinfo returns multiple address
    # families (e.g. IPv4 and IPv6), then you should make sure that your first
    # and second attempts use different families:
    #
    #    https://tools.ietf.org/html/rfc6555#section-5.4
    #
    # This function post-processes the results from getaddrinfo, in-place, to
    # satisfy this requirement.
    for i in range(1, len(targets)):
        if targets[i][0] != targets[0][0]:
            # Found the first entry with a different address family; move it
            # so that it becomes the second item on the list.
            if i != 1:
                targets.insert(1, targets.pop(i))
            break

async def open_quic_connection(
    host: str | bytes,
    port: int,
    *,
    configuration: Optional[QuicConfiguration] = None,
    happy_eyeballs_delay: float = 0.300,  # default from Chrome and Firefox,
                                          # see: https://tools.ietf.org/html/rfc6555#section-6
) -> SimpleQuicConnection:
    """
    Connect to the given host and port over QUIC.

    Modeled after `trio.open_tcp_stream` for connecting to TCP endpoints and borrowing heavily from it.

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
        msg = f"no results found for hostname lookup: {format_host_port(host, port)}"
        raise OSError(msg)

    reorder_for_rfc_6555_section_5_4(targets)

    # This list records all the connection failures that we ignored.
    oserrors: list[OSError] = []

    # Keeps track of the socket that we're going to complete with,
    # need to make sure this isn't automatically closed
    winning_socket: trio.socket.SocketType | None = None
    winning_address: Any = None

    # Try connecting to the specified address. Possible outcomes:
    # - success: record connected socket in winning_socket and cancel
    #   concurrent attempts
    # - failure: record exception in oserrors, set attempt_failed allowing
    #   the next connection attempt to start early
    # code needs to ensure sockets can be closed appropriately in the
    # face of crash or cancellation
    async def attempt_udp_connect(
        socket_args: tuple[socket.AddressFamily, socket.SocketKind, int],
        sockaddr: Any,
        attempt_failed: trio.Event,
    ) -> None:
        nonlocal winning_socket
        nonlocal winning_address

        try:
            assert ( socket_args[1] == trio.socket.SOCK_DGRAM ), "only working with UDP sockets"
            sock = trio.socket.socket(*socket_args)
            open_sockets.add(sock)

            # if local_address is not None:
            #     # TCP connections are identified by a 4-tuple:
            #     #
            #     #   (local IP, local port, remote IP, remote port)
            #     #
            #     # So if a single local IP wants to make multiple connections
            #     # to the same (remote IP, remote port) pair, then those
            #     # connections have to use different local ports, or else TCP
            #     # won't be able to tell them apart. OTOH, if you have multiple
            #     # connections to different remote IP/ports, then those
            #     # connections can share a local port.
            #     #
            #     # Normally, when you call bind(), the kernel will immediately
            #     # assign a specific local port to your socket. At this point
            #     # the kernel doesn't know which (remote IP, remote port)
            #     # you're going to use, so it has to pick a local port that
            #     # *no* other connection is using. That's the only way to
            #     # guarantee that this local port will be usable later when we
            #     # call connect(). (Alternatively, you can set SO_REUSEADDR to
            #     # allow multiple nascent connections to share the same port,
            #     # but then connect() might fail with EADDRNOTAVAIL if we get
            #     # unlucky and our TCP 4-tuple ends up colliding with another
            #     # unrelated connection.)
            #     #
            #     # So calling bind() before connect() works, but it disables
            #     # sharing of local ports. This is inefficient: it makes you
            #     # more likely to run out of local ports.
            #     #
            #     # But on some versions of Linux, we can re-enable sharing of
            #     # local ports by setting a special flag. This flag tells
            #     # bind() to only bind the IP, and not the port. That way,
            #     # connect() is allowed to pick the the port, and it can do a
            #     # better job of it because it knows the remote IP/port.
            #     with suppress(OSError, AttributeError):
            #         sock.setsockopt(
            #             trio.socket.IPPROTO_IP,
            #             trio.socket.IP_BIND_ADDRESS_NO_PORT,
            #             1,
            #         )
            #     try:
            #         await sock.bind((local_address, 0))
            #     except OSError:
            #         raise OSError(
            #             f"local_address={local_address!r} is incompatible "
            #             f"with remote address {sockaddr!r}",
            #         ) from None

            await sock.connect(sockaddr)

            # Success! Save the winning socket and cancel all outstanding
            # connection attempts.
            winning_socket = sock
            winning_address = sockaddr
            nursery.cancel_scope.cancel()
        except OSError as exc:
            # This connection attempt failed, but the next one might
            # succeed. Save the error for later so we can report it if
            # everything fails, and tell the next attempt that it should go
            # ahead (if it hasn't already).
            oserrors.append(exc)
            attempt_failed.set()

    with close_all() as open_sockets:
        # nursery spawns a task for each connection attempt, will be
        # cancelled by the task that gets a successful connection
        async with trio.open_nursery() as nursery:
            for address_family, socket_type, proto, _, addr in targets:
                # create an event to indicate connection failure,
                # allowing the next target to be tried early
                this_attempt_failed = trio.Event()
                nursery.start_soon(
                    attempt_udp_connect,
                    (address_family, socket_type, proto),
                    addr,
                    this_attempt_failed,
                )
                # give this attempt at most this time before moving on
                with trio.move_on_after(happy_eyeballs_delay):
                    await this_attempt_failed.wait()

        # nothing succeeded
        if winning_socket is None:
            assert len(oserrors) == len(targets)
            msg = f"all attempts to connect to {format_host_port(host, port)} failed"
            raise OSError(msg) from ExceptionGroup(msg, oserrors)
        else:
            client = SimpleQuicConnection(winning_socket, winning_address,
                                          configuration=client_configuration)
            open_sockets.remove(winning_socket)
            return client
