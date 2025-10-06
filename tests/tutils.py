#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

# Utilities for testing
import socket as stdlib_socket
import pytest

try:
    s = stdlib_socket.socket(stdlib_socket.AF_INET6, stdlib_socket.SOCK_STREAM, 0)
except OSError:  # pragma: no cover
    # Some systems don't even support creating an IPv6 socket, let alone
    # binding it. (ex: Linux with 'ipv6.disable=1' in the kernel command line)
    # We don't have any of those in our CI, and there's nothing that gets
    # tested _only_ if can_create_ipv6 = False, so we'll just no-cover this.
    can_create_ipv6 = False
    can_bind_ipv6 = False
else:
    can_create_ipv6 = True
    with s:
        try:
            s.bind(("::1", 0))
        except OSError:  # pragma: no cover # since support for 3.7 was removed
            can_bind_ipv6 = False
        else:
            can_bind_ipv6 = True

creates_ipv6 = pytest.mark.skipif(not can_create_ipv6, reason="need IPv6")
binds_ipv6 = pytest.mark.skipif(not can_bind_ipv6, reason="need IPv6")
