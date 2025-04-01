import pytest

from trioquic.crypto import decode_var_length_int
from trioquic.frame import encode_var_length_int, QuicFrame, QuicFrameType
from trioquic.packet import QuicPacket


def test_var_int_encoding():
    assert decode_var_length_int(bytes.fromhex("c2197c5eff14e88c")) == (int("151,288,809,941,952,652".replace(",", "")), 8)
    assert decode_var_length_int(bytes.fromhex("9d7f3e7d")) == (int("494,878,333".replace(",", "")), 4)
    assert decode_var_length_int(bytes.fromhex("7bbd")) == (int("15,293".replace(",", "")), 2)
    assert decode_var_length_int(bytes.fromhex("25")) == (37, 1)
    assert decode_var_length_int(bytes.fromhex("4025")) == (37, 2)

    assert encode_var_length_int(63) == b'\x3f'
    assert encode_var_length_int(64) == b'\x40\x40'
    assert encode_var_length_int(16383) == b'\x7f\xff'
    assert encode_var_length_int(16384) == b'\x80\x00\x40\x00'
    assert len(encode_var_length_int(2 ** 30 - 1)) == 4
    assert len(encode_var_length_int(2 ** 30)) == 8

    with pytest.raises(ValueError):
        encode_var_length_int(-5)
    with pytest.raises(ValueError):
        encode_var_length_int(2 ** 63)

def test_no_content():

    frame = QuicFrame(QuicFrameType.PADDING, content=None)
    assert frame.encode() == b'\x00'
    with pytest.raises(ValueError):
        QuicFrame(QuicFrameType.PADDING, content=b'not allowed')

    frame = QuicFrame(QuicFrameType.PING)
    assert frame.content is None
    assert frame.encode() == b'\x01'

    frame = QuicFrame.decode(bytes.fromhex("01"))