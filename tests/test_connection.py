import pytest

from trioquic.configuration import QuicConfiguration
from trioquic.connection import QuicConnection


def test_wrong_client_conf1():
    with pytest.raises(AssertionError):
        QuicConnection(
            configuration=QuicConfiguration(is_client=True),
            original_destination_connection_id=b'bad')

def test_wrong_client_conf2():
    with pytest.raises(AssertionError):
        QuicConnection(
            configuration=QuicConfiguration(is_client=True),
            retry_source_connection_id=b'bad')

def test_wrong_server_conf():
    with pytest.raises(AssertionError):
        QuicConnection(
            configuration=QuicConfiguration(is_client=False)
        )
