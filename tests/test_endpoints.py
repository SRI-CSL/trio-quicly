#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from contextlib import asynccontextmanager
from unittest import skipIf

import trio
from typing import *
import pytest

from quicly.configuration import QuicConfiguration
from quicly.endpoint import QuicServer, QuicClient, QuicEndpoint
from quicly.connection import SimpleQuicConnection, ConnectionState
from quicly.server import open_quic_servers
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
        delay: int = 0,
        transport_parameters: dict[str | int, int | bool] | None = None,
) -> AsyncGenerator[tuple[QuicServer, tuple[str, int]], None]:
    with local_endpoint(ipv6=ipv6) as server_endpoint:
        server = cast(QuicServer, server_endpoint)
        await server.socket.bind(server.address)

        async with trio.open_nursery() as nursery:
            async def echo_handler(server_channel: SimpleQuicConnection) -> None:
                # print(
                #     "echo handler started: "
                #     f"server {server_stream.endpoint.socket.getsockname()!r} and "
                #     f"client {server_stream.remote_address!r}",
                # )
                try:
                    # print("server starting do_handshake")
                    # await server_stream.do_handshake()
                    # print("server finished do_handshake")
                    # TODO: if DATAGRAM supported, use channel semantics, otherwise stream semantics:
                    if server_channel.configuration.transport_local.max_datagram_frame_size:
                        async for packet in server_channel:
                            # print(f"echoing {packet!r} -> {server_stream.remote_address!r}")
                            await trio.sleep(delay)
                            await server_channel.send(packet)
                    else:
                        async for packet in server_channel.iter_stream_chunks():
                            # print(f"echoing {packet!r} -> {server_stream.remote_address!r}")
                            await trio.sleep(delay)
                            await server_channel.send_all(packet)
                except trio.BrokenResourceError:  # pragma: no cover
                    print("echo handler channel broken")

            server_config = QuicConfiguration(is_client=False, ipv6=ipv6)
            server_config.update_local(transport_parameters)
            await nursery.start(server.serve, echo_handler, nursery, server_config, )

            yield server, server.socket.getsockname()

            if autocancel:
                nursery.cancel_scope.cancel()

# TODO: @parametrize_ipv6, also remove = False default below
async def test_smoke_datagram(ipv6: bool = False) -> None:
    transport_parameters = {"max_datagram_frame_size" : 1200}  # add DATAGRAM support
    async with quic_echo_server(True, ipv6=ipv6, delay=0,
                                transport_parameters=transport_parameters) as (_server_endpoint, address):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            client_config = QuicConfiguration(is_client=True, ipv6=ipv6)
            client_config.update_local(transport_parameters)
            async with client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                      client_config) as client_channel:
                assert client_channel.state == ConnectionState.ESTABLISHED
                # exercise back and forth
                await client_channel.send(b"hello")
                answer = await client_channel.receive()
                assert answer == b"hello"
                await client_channel.send(b"goodbye")
                answer = await client_channel.receive()
                assert answer == b"goodbye"

# TODO: test_fast_start (sending bytes with INITIAL...)

async def test_one_sided_datagram1(ipv6: bool = False) -> None:
    transport_parameters = {"max_datagram_frame_size" : 2400}  # add DATAGRAM support
    async with quic_echo_server(True, ipv6=ipv6, delay=0,
                                transport_parameters=transport_parameters) as (_server_endpoint, address):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            client_config = QuicConfiguration(is_client=True, ipv6=ipv6)
            client_config.update_local(transport_parameters)
            async with client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                      client_config) as connection:
                assert connection.state == ConnectionState.ESTABLISHED
                await trio.sleep(0.1)  # let handshake finalize for server
                # server changes to not supporting DATAGRAM:
                server = cast(QuicServer, _server_endpoint)
                assert connection.host_cid in server._connections.keys()
                server_connection = server._connections[connection.host_cid]
                assert server_connection.state == ConnectionState.ESTABLISHED
                server_connection.configuration.update_local({"max_datagram_frame_size" : 0})
                await connection.send(b"hello")
                # TODO: PROTOCOL_VIOLATION!
                await trio.sleep_forever() # let server close connection with PROTOCOL_VIOLATION

async def test_one_sided_datagram2(ipv6: bool = False) -> None:
    # server does not support DATAGRAM:
    async with quic_echo_server(True, ipv6=ipv6, delay=0) as (_server_endpoint, address):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            client_config = QuicConfiguration(is_client=True, ipv6=ipv6)
            client_config.update_local({"max_datagram_frame_size" : 2400})
            async with client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                      client_config) as connection:
                await connection.send(b"hello")
                await trio.sleep(1) # let server close connection with PROTOCOL_VIOLATION

# TODO: @parametrize_ipv6, also remove = False default below
async def test_handshake_datagram(ipv6: bool = False) -> None:
    transport_parameters = {"max_datagram_frame_size" : 2400}  # add DATAGRAM support
    async with quic_echo_server(True, ipv6=ipv6, delay=0,
                                transport_parameters=transport_parameters) as (_server_endpoint, address):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            client_config = QuicConfiguration(is_client=True, ipv6=ipv6)
            client_config.update_local(transport_parameters)
            async with client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                      client_config) as connection:
                assert connection.state == ConnectionState.ESTABLISHED
                await trio.sleep(0.1)  # let handshake finalize for server
                server = cast(QuicServer, _server_endpoint)
                assert connection.host_cid in server._connections.keys()
                server_connection = server._connections[connection.host_cid]
                assert server_connection.state == ConnectionState.ESTABLISHED
            await trio.sleep(0.5)  # let closing() commence?
            print(f"client state: {connection.state}")

            # TODO: check cleanly shutdown?

@parametrize_ipv6
async def test_handshake(ipv6: bool) -> None:
    async with quic_echo_server(True, ipv6=ipv6, delay=0) as (_server_endpoint, address):
        with local_endpoint(ipv6=ipv6, is_client=True) as client_endpoint:
            client = cast(QuicClient, client_endpoint)
            async with client.connect((get_localhost(ipv6, use_wildcard=False),) + address[1:],
                                      QuicConfiguration(is_client=True)) as connection:
                assert connection.state == ConnectionState.ESTABLISHED
                await trio.sleep(0.5)  # let handshake finalize for server
                server = cast(QuicServer, _server_endpoint)
                assert connection.host_cid in server._connections.keys()
                server_connection = server._connections[connection.host_cid]
                assert server_connection.state == ConnectionState.ESTABLISHED
            # TODO: check cleanly shutdown?