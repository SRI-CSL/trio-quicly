import pytest
import trio

from .tutils import binds_ipv6
from trioquic.server import open_quic_servers

parametrize_ipv6 = pytest.mark.parametrize(
    "ipv6",
    [False, pytest.param(True, marks=binds_ipv6)],
    ids=["ipv4", "ipv6"],
)

@parametrize_ipv6
async def test_open_one_quic_server(ipv6: bool):
    host = "::" if ipv6 else "0.0.0.0"
    servers = await open_quic_servers(0, host=host)
    assert len(servers) == 1, "if host is not None, only bind to either IPv4 or IPv6 localhost"
    server = servers[0]
    if ipv6:
        assert server.socket.getsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY) == 1, "only support IPv6"

async def test_wildcard_quic_server():
    servers = await open_quic_servers(0, host=None)

    assert len(servers) >= 1, "at least one if not more servers for wildcard"
    for server in servers:
        if server.socket.family == trio.socket.AF_INET6:
            assert server.socket.getsockopt(trio.socket.IPPROTO_IPV6, trio.socket.IPV6_V6ONLY) == 0, "support IPv6"