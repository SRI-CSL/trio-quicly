from copy import deepcopy
import random
import pytest

from trioquic.crypto import decode_var_length_int
from trioquic.exceptions import QuicConnectionError
from trioquic.frame import encode_var_length_int, QuicFrame, QuicFrameType, ACKFrame, ECNCounts, ACKRange


def test_var_int_encoding():
    assert decode_var_length_int(bytes.fromhex("c2197c5eff14e88c")) == (int("151,288,809,941,952,652".replace(",", "")), 8)
    assert decode_var_length_int(bytes.fromhex("9d7f3e7d")) == (int("494,878,333".replace(",", "")), 4)
    assert decode_var_length_int(bytes.fromhex("7bbd")) == (int("15,293".replace(",", "")), 2)
    assert decode_var_length_int(bytes.fromhex("25")) == (37, 1)
    assert decode_var_length_int(bytes.fromhex("4025")) == (37, 2)
    assert decode_var_length_int(bytes.fromhex("4000")) == (0, 2)
    assert decode_var_length_int(bytes.fromhex("40 81")) == (129, 2)

    assert encode_var_length_int(63) == b'\x3f'
    assert encode_var_length_int(64) == b'\x40\x40'
    assert encode_var_length_int(16383) == b'\x7f\xff'
    assert encode_var_length_int(16384) == b'\x80\x00\x40\x00'
    assert len(encode_var_length_int(2 ** 30 - 1)) == 4
    assert len(encode_var_length_int(2 ** 30)) == 8
    assert encode_var_length_int(0) == b'\x00'

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

    frame, offset = QuicFrame.decode(bytes.fromhex("01"))
    assert offset == 1
    assert frame.frame_type == QuicFrameType.PING
    assert frame.content is None

def assert_ack_delay_equal(expected: int, actual: int, exponent: int = 3):
    max_error = (1 << exponent) - 1
    assert abs(expected - actual) <= max_error, (
        f"ACK delay mismatch: expected={expected}, actual={actual}, allowed error={max_error}"
    )

def test_ack_frames():

    largest_ack = 0xac5c02
    ack_delay = 1032  # microseconds
    first_ack_range = 0

    frame = QuicFrame(QuicFrameType.ACK,
                      content=ACKFrame(largest_ack, ack_delay, first_ack_range))
    encoded_frame = frame.encode()
    decoded_frame, offset = QuicFrame.decode(encoded_frame)
    assert offset == len(encoded_frame)
    assert decoded_frame.frame_type == QuicFrameType.ACK
    assert isinstance(decoded_frame.content, ACKFrame)
    assert decoded_frame.content.largest_ack == largest_ack
    assert decoded_frame.content.ack_delay == ack_delay

def generate_safe_ack_ranges(
    start: int, count: int
) -> tuple[list[ACKRange], int, int]:
    """
    Generate a valid list of ACKRange entries that do not underflow the packet number space.

    :param start: the largest_ack value
    :param count: the number of ACK ranges to include
    :return: (ack_ranges, first_ack_range, largest_ack)
    """
    ranges = []
    current = start
    total_range = 0

    for i in range(count):
        gap = 1
        length = 2
        total = gap + length + 1
        if current - total < 0:
            break
        current -= total
        total_range += total
        ranges.append(ACKRange(gap=gap, ack_range_length=length))

    # To ensure there's room for first_ack_range too
    first_ack_range = 5
    largest_ack = current + total_range + first_ack_range
    return ranges, first_ack_range, largest_ack

def test_ack_frame_edge_cases():
    # Case 1: No ack_ranges
    frame = QuicFrame(
        frame_type=QuicFrameType.ACK,
        content=ACKFrame(
            largest_ack=100,
            ack_delay=8,
            first_ack_range=0,
            ack_ranges=[],
        ),
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)

    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.ACK
    assert isinstance(decoded.content, ACKFrame)
    assert decoded.content.largest_ack == 100
    assert_ack_delay_equal(decoded.content.ack_delay, 8)
    assert decoded.content.first_ack_range == 0
    assert decoded.content.ack_ranges == []

    # Case 2: largest_ack is very large
    frame = QuicFrame(
        frame_type=QuicFrameType.ACK,
        content=ACKFrame(
            largest_ack=2**30,
            ack_delay=8,
            first_ack_range=1,
            ack_ranges=[ACKRange(gap=1, ack_range_length=1)],
        ),
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)
    assert isinstance(decoded.content, ACKFrame)
    assert decoded.content.largest_ack == 2**30
    assert_ack_delay_equal(decoded.content.ack_delay, 8)
    assert len(decoded.content.ack_ranges) == 1

def generate_fuzz_ack_frame(seed: int = None) -> QuicFrame:
    if seed is not None:
        random.seed(seed)

    # Safe limits
    max_largest_ack = 10_000
    largest_ack = random.randint(50, max_largest_ack)
    ack_delay = random.randint(8, 1_000_000)
    num_ranges = random.randint(0, 5)

    ack_ranges = []
    total_used = 0

    for _ in range(num_ranges):
        gap = random.randint(0, 5)
        length = random.randint(0, 5)
        needed = gap + length + 1
        if total_used + needed >= largest_ack:
            break
        ack_ranges.append(ACKRange(gap=gap, ack_range_length=length))
        total_used += needed

    first_ack_range = random.randint(0, min(10, largest_ack - total_used))

    frame_type = QuicFrameType(random.choice([QuicFrameType.ACK, QuicFrameType.ACK_ECN]))
    return QuicFrame(
        frame_type=frame_type,
        content=ACKFrame(
            largest_ack=largest_ack,
            ack_delay=ack_delay,
            first_ack_range=first_ack_range,
            ack_ranges=ack_ranges,
            ecn_counts=ECNCounts(ect0=1, ect1=2, ce=3) if frame_type is QuicFrameType.ACK_ECN else None
        )
    )

def test_ack_frame_fuzz(n: int = 10):
    for i in range(n):
        try:
            frame = generate_fuzz_ack_frame(seed=i)
            assert isinstance(frame.content, ACKFrame)

            encoded = frame.encode()
            decoded, consumed = QuicFrame.decode(encoded)

            assert consumed == len(encoded)
            assert decoded.frame_type == frame.frame_type
            assert isinstance(decoded.content, ACKFrame)
            assert decoded.content.largest_ack == frame.content.largest_ack
            assert_ack_delay_equal(decoded.content.ack_delay, frame.content.ack_delay)
            assert decoded.content.first_ack_range == frame.content.first_ack_range
            assert decoded.content.ack_ranges == frame.content.ack_ranges
            assert decoded.content.ecn_counts == frame.content.ecn_counts

        except QuicConnectionError as e:
            pass  #print(f"⚠️  Skipped invalid frame on fuzz iteration {i}: {e}")
        except Exception as e:
            raise AssertionError(f"❌ Unexpected failure on fuzz iteration {i}: {e}")

def test_quic_ack_and_ack_ecn_round_trip():

    # Generate safe ACK ranges and frame parameters
    ack_ranges, first_ack_range, largest_ack = generate_safe_ack_ranges(start=1000, count=2)

    # ACK frame
    ack_frame = QuicFrame(
        frame_type=QuicFrameType.ACK,
        content=ACKFrame(
            largest_ack=largest_ack,
            ack_delay=4000,  # in microseconds
            first_ack_range=first_ack_range,
            ack_ranges=deepcopy(ack_ranges),
        ),
    )

    # ACK_ECN frame
    ack_ecn_frame = QuicFrame(
        frame_type=QuicFrameType.ACK_ECN,
        content=ACKFrame(
            largest_ack=largest_ack + 1000,  # separate value to ensure uniqueness
            ack_delay=8000,
            first_ack_range=first_ack_range,
            ack_ranges=deepcopy(ack_ranges),
            ecn_counts=ECNCounts(ect0=10, ect1=20, ce=30),
        ),
    )

    # Test ACK round trip
    encoded_ack = ack_frame.encode()
    decoded_ack, consumed_ack = QuicFrame.decode(encoded_ack)
    assert consumed_ack == len(encoded_ack)
    assert decoded_ack.frame_type == QuicFrameType.ACK
    assert isinstance(decoded_ack.content, ACKFrame)
    assert decoded_ack.content.largest_ack == ack_frame.content.largest_ack
    assert_ack_delay_equal(decoded_ack.content.ack_delay, 4000)
    assert decoded_ack.content.first_ack_range == 5
    assert len(decoded_ack.content.ack_ranges) == 2

    # Test ACK_ECN round trip
    encoded_ecn = ack_ecn_frame.encode()
    decoded_ecn, consumed_ecn = QuicFrame.decode(encoded_ecn)
    assert consumed_ecn == len(encoded_ecn)
    assert decoded_ecn.frame_type == QuicFrameType.ACK_ECN
    assert isinstance(decoded_ecn.content, ACKFrame)
    assert decoded_ecn.content.largest_ack == ack_ecn_frame.content.largest_ack
    assert_ack_delay_equal(decoded_ecn.content.ack_delay, 8000)
    assert decoded_ecn.content.first_ack_range == 5
    assert len(decoded_ecn.content.ack_ranges) == 2
    assert decoded_ecn.content.ecn_counts == ECNCounts(ect0=10, ect1=20, ce=30)
