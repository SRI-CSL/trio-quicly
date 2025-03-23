from contextlib import asynccontextmanager
import socket as psocket
import trio
from typing import *
import pytest

from trioquic.configuration import QuicConfiguration
from trioquic.connection import QuicServer, QuicClient, QuicEndpoint, SimpleQuicConnection
from trioquic.server import open_quic_servers
from .tutils import binds_ipv6

parametrize_ipv6 = pytest.mark.parametrize(
    "ipv6",
    [False, pytest.param(True, marks=binds_ipv6)],
    ids=["ipv4", "ipv6"],
)

def get_localhost(ipv6: bool, use_wildcard: bool = False) -> str:
    if use_wildcard:
        return "::" if ipv6 else "0.0.0.0"
    else:
        return "::1" if ipv6 else "127.0.0.1"

def local_endpoint(ipv6: bool, port: int = 0, is_client: bool = False) -> QuicEndpoint:
    endpoint_socket = trio.socket.socket(family=trio.socket.AF_INET6 if ipv6 else trio.socket.AF_INET,
                                         type=trio.socket.SOCK_DGRAM,
                                         proto=trio.socket.IPPROTO_UDP)
    if is_client:
        return QuicClient(endpoint_socket)
    else:
        return QuicServer(endpoint_socket, (get_localhost(ipv6, True), port))

@parametrize_ipv6
async def test_open_one_quic_server(ipv6: bool):
    servers = await open_quic_servers(0, host=get_localhost(ipv6, use_wildcard=True))
    assert len(servers) == 1, "if host is not None, only bind to either IPv4 or IPv6 localhost"
    server = servers[0]
    if ipv6:
        assert server.socket.getsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY) == 1, "only support IPv6"
    # else:
        # UDP datagrams MUST NOT be fragmented at the IP layer. In IPv4, the Don't Fragment (DF) bit MUST be set
        # if possible, to prevent fragmentation on the path.
        #df_status = server.socket.getsockopt(trio.socket.IPPROTO_IP, psocket.socket.IP_MTU_DISCOVER)
        #print(df_status)  # Expected Output: 2 (which corresponds to IP_PMTUDISC_DO)
        #assert server.socket.getsockopt(trio.socket.IPPROTO_IP, ) == 2, "DF bit set"

async def test_wildcard_quic_server():
    servers = await open_quic_servers(0, host=None)

    assert len(servers) >= 1, "at least one if not more servers for wildcard"
    for server in servers:
        if server.socket.family == trio.socket.AF_INET6:
            assert server.socket.getsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY) == 0, "support IPv6"

@asynccontextmanager
async def quic_echo_server(
    autocancel: bool = True,
    ipv6: bool = False,
    delay: int = 0
) -> AsyncGenerator[tuple[QuicServer, tuple[str, int]], None]:
    with local_endpoint(ipv6=ipv6) as server_endpoint:
        server = cast(QuicServer, server_endpoint)
        await server.socket.bind(server.address)

        async with trio.open_nursery() as nursery:
            async def echo_handler(server_stream: SimpleQuicConnection) -> None:
                # print(
                #     "echo handler started: "
                #     f"server {server_stream.endpoint.socket.getsockname()!r} and "
                #     f"client {server_stream.remote_address!r}",
                # )
                try:
                    # print("server starting do_handshake")
                    # await server_stream.do_handshake()
                    # print("server finished do_handshake")
                    async for packet in server_stream:
                        # print(f"echoing {packet!r} -> {server_stream.remote_address!r}")
                        await trio.sleep(delay)
                        await server_stream.send_all(packet)
                except trio.BrokenResourceError:  # pragma: no cover
                    print("echo handler channel broken")

            await nursery.start(server.serve, echo_handler, nursery)

            yield server, server.socket.getsockname()

            if autocancel:
                nursery.cancel_scope.cancel()

@parametrize_ipv6
async def test_smoke(ipv6: bool) -> None:
    async with (quic_echo_server(True, ipv6=ipv6, delay=1) as (_server_endpoint, address)):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            client_channel = await client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                                  QuicConfiguration(is_client=True))

            async with client_channel:
                await client_channel.send_all(b"hello")
                answer = await client_channel.receive_some()
                assert answer == b"hello"
                await client_channel.send_all(b"goodbye")
                assert await client_channel.receive_some() == b"goodbye"

# @parametrize_ipv6
async def test_handshake(ipv6: bool = False) -> None:
    async with (quic_echo_server(True, ipv6=ipv6) as (_server_endpoint, address)):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            await client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                 QuicConfiguration(is_client=True))
