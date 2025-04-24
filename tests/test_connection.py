#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

import pytest

from quicly.configuration import QuicConfiguration
from quicly.connection import SimpleQuicConnection


# def test_wrong_client_conf1():
#     with pytest.raises(AssertionError):
#         SimpleQuicConnection(
#             configuration=QuicConfiguration(is_client=True),
#             original_destination_connection_id=b'bad')
#
# def test_wrong_client_conf2():
#     with pytest.raises(AssertionError):
#         SimpleQuicConnection(
#             configuration=QuicConfiguration(is_client=True),
#             retry_source_connection_id=b'bad')
#
# def test_wrong_server_conf():
#     with pytest.raises(AssertionError):
#         SimpleQuicConnection(
#             configuration=QuicConfiguration(is_client=False)
#         )

def test_no_endpoint():
    with pytest.raises(AssertionError):
        SimpleQuicConnection(None, ("bla", 12345), 0, QuicConfiguration())
