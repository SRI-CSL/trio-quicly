#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

import random
from copy import deepcopy

from quicly.exceptions import QuicConnectionError
from quicly.frame import encode_var_length_int, decode_var_length_int, QuicFrame, QuicFrameType, ACKFrame, ECNCounts, \
    ACKRange, \
    StreamFrame, MaxDataFrame, MaxStreamData, StopSendingFrame, MaxStreamsBidiFrame, MaxStreamsUniFrame, \
    DataBlockedFrame, StreamsBlockedBidiFrame, StreamsBlockedUniFrame, RetireConnectionIDFrame, StreamDataBlockedFrame, \
    ConnectionCloseFrame, NewConnectionIDFrame, parse_all_quic_frames, DatagramFrame


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

def test_stream_frame_flag_combinations():
    from itertools import product

    stream_id = 42
    offset = 1337
    data = b'hello stream'

    for fin, len_flag, off in product([False, True], repeat=3):
        # Manually build a frame with the flags
        frame = QuicFrame(
            frame_type=QuicFrameType.STREAM_BASE,  # the type will be determined during encode
            content=StreamFrame(
                stream_id=stream_id,
                offset=offset if off else 0,
                fin=fin,
                data=data,
                include_length=len_flag,
            )
        )

        encoded = frame.encode()
        decoded, consumed = QuicFrame.decode(encoded)

        assert consumed == len(encoded)
        assert decoded.frame_type == QuicFrameType.STREAM_BASE
        assert isinstance(decoded.content, StreamFrame)
        sf = decoded.content
        assert sf.stream_id == stream_id
        assert sf.offset == (offset if off else 0)
        assert sf.fin == fin
        assert sf.data == data
        assert sf.include_length == len_flag

def test_max_data_frame_round_trip():
    max_data_value = 65535  # example value

    frame = QuicFrame(
        frame_type=QuicFrameType.MAX_DATA,
        content=MaxDataFrame(max_data=max_data_value)
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)

    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.MAX_DATA
    assert isinstance(decoded.content, MaxDataFrame)
    assert decoded.content.max_data == max_data_value

def test_max_stream_data_frame_round_trip():
    stream_id = 1234
    max_stream_data = 65536

    frame = QuicFrame(
        frame_type=QuicFrameType.MAX_STREAM_DATA,
        content=MaxStreamData(stream_id=stream_id, max_stream_data=max_stream_data)
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)

    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.MAX_STREAM_DATA
    assert isinstance(decoded.content, MaxStreamData)
    assert decoded.content.stream_id == stream_id
    assert decoded.content.max_stream_data == max_stream_data

SINGLE_STREAM_VARINT_FRAMES = {
    QuicFrameType.MAX_STREAM_DATA: MaxStreamData,
    QuicFrameType.STOP_SENDING: StopSendingFrame,
    # Add other stream-related frames as needed...
}
def test_stream_id_varint_frame_round_trip():
    for frame_type, frame_cls in SINGLE_STREAM_VARINT_FRAMES.items():
        stream_id = random.randint(0, 2**16)
        value = random.randint(0, 2**20)

        frame = QuicFrame(
            frame_type=frame_type,
            content=frame_cls(stream_id, value)
        )

        encoded = frame.encode()
        decoded, consumed = QuicFrame.decode(encoded)

        assert consumed == len(encoded)
        assert decoded.frame_type == frame_type
        assert isinstance(decoded.content, frame_cls)
        assert decoded.content.stream_id == stream_id

        # Check the second field based on frame class
        if frame_type == QuicFrameType.MAX_STREAM_DATA:
            assert decoded.content.max_stream_data == value
        elif frame_type == QuicFrameType.STOP_SENDING:
            assert decoded.content.app_error == value


FRAME_TYPES_AND_FIELDS = {
    QuicFrameType.MAX_DATA: ("max_data", MaxDataFrame),
    QuicFrameType.MAX_STREAMS_BIDI: ("max_streams", MaxStreamsBidiFrame),
    QuicFrameType.MAX_STREAMS_UNI: ("max_streams", MaxStreamsUniFrame),
    QuicFrameType.DATA_BLOCKED: ("data_limit", DataBlockedFrame),
    QuicFrameType.STREAMS_BLOCKED_BIDI: ("limit", StreamsBlockedBidiFrame),
    QuicFrameType.STREAMS_BLOCKED_UNI: ("limit", StreamsBlockedUniFrame),
    QuicFrameType.RETIRE_CONNECTION_ID: ("sequence_number", RetireConnectionIDFrame),
}
def test_single_varint_named_frames_round_trip():
    for frame_type, (field_name, frame_cls) in FRAME_TYPES_AND_FIELDS.items():
        value = random.randint(0, 2**30)

        frame = QuicFrame(
            frame_type=frame_type,
            content=frame_cls(**{field_name: value})
        )

        encoded = frame.encode()
        decoded, consumed = QuicFrame.decode(encoded)
        assert consumed == len(encoded)
        assert decoded.frame_type == frame_type
        assert isinstance(decoded.content, frame_cls)
        assert getattr(decoded.content, field_name) == value

def test_stream_data_blocked_frame_round_trip():
    stream_id = 1234
    max_stream_data = 987654321

    frame = QuicFrame(
        frame_type=QuicFrameType.STREAM_DATA_BLOCKED,
        content=StreamDataBlockedFrame(stream_id=stream_id, max_stream_data=max_stream_data)
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)
    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.STREAM_DATA_BLOCKED
    assert isinstance(decoded.content, StreamDataBlockedFrame)
    assert decoded.content.stream_id == stream_id
    assert decoded.content.max_stream_data == max_stream_data

def test_connection_close_frame_round_trip():
    reason = b"stream reset due to timeout"
    errno = 42
    frame_type = 0x08  # Example: STREAM frame

    # Test for Transport Close
    frame = QuicFrame(
        frame_type=QuicFrameType.TRANSPORT_CLOSE,
        content=ConnectionCloseFrame(errno=errno, frame_type=frame_type, reason=reason)
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)
    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.TRANSPORT_CLOSE
    assert isinstance(decoded.content, ConnectionCloseFrame)
    assert decoded.content.errno == errno
    assert decoded.content.frame_type == frame_type
    assert decoded.content.reason == reason

    frame = QuicFrame(
        frame_type=QuicFrameType.APPLICATION_CLOSE,
        content=ConnectionCloseFrame(errno=errno, frame_type=None, reason=reason)
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)
    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.APPLICATION_CLOSE
    assert isinstance(decoded.content, ConnectionCloseFrame)
    assert decoded.content.errno == errno
    assert decoded.content.frame_type is None
    assert decoded.content.reason == reason

def test_new_connection_id_frame_round_trip():
    seq_no = 5
    retire_prior_to = 2
    connection_id = b"\x11\x22\x33\x44\x55"
    reset_token = b"\xaa" * 16

    frame = QuicFrame(
        frame_type=QuicFrameType.NEW_CONNECTION_ID,
        content=NewConnectionIDFrame(
            seq_no=seq_no,
            retire_prior_to=retire_prior_to,
            connection_id=connection_id,
            reset_token=reset_token
        )
    )

    encoded = frame.encode()
    decoded, consumed = QuicFrame.decode(encoded)
    assert consumed == len(encoded)
    assert decoded.frame_type == QuicFrameType.NEW_CONNECTION_ID
    assert isinstance(decoded.content, NewConnectionIDFrame)
    assert decoded.content.seq_no == seq_no
    assert decoded.content.retire_prior_to == retire_prior_to
    assert decoded.content.connection_id == connection_id
    assert decoded.content.reset_token == reset_token

import pytest

def test_new_connection_id_frame_validation_errors():
    # ❌ Empty connection ID
    with pytest.raises(ValueError, match="non-empty connection ID"):
        NewConnectionIDFrame(
            seq_no=0,
            retire_prior_to=0,
            connection_id=b"",
            reset_token=b"\x00" * 16,
        )

    # ❌ Too-long connection ID (> 20 bytes)
    with pytest.raises(ValueError, match="too long connection ID"):
        NewConnectionIDFrame(
            seq_no=0,
            retire_prior_to=0,
            connection_id=b"\x00" * 21,
            reset_token=b"\x00" * 16,
        )

    # ❌ Invalid reset token length (≠ 16 bytes)
    with pytest.raises(ValueError, match="reset token must be exactly 16 bytes"):
        NewConnectionIDFrame(
            seq_no=0,
            retire_prior_to=0,
            connection_id=b"\x01\x02",
            reset_token=b"\x00" * 15,
        )

def test_transport_close_defaults_unknown_trigger_to_padding():
    cc = ConnectionCloseFrame(errno=42, reason=b"oops", frame_type=None)
    qf = QuicFrame(QuicFrameType.TRANSPORT_CLOSE, content=cc)
    assert isinstance(qf.content, ConnectionCloseFrame)
    # Unknown trigger should become PADDING (0x00)
    assert qf.content.frame_type == QuicFrameType.PADDING

def test_transport_close_preserves_explicit_trigger():
    cc = ConnectionCloseFrame(errno=1, reason=b"err", frame_type=QuicFrameType.PING)
    qf = QuicFrame(QuicFrameType.TRANSPORT_CLOSE, cc)
    assert qf.content.frame_type == QuicFrameType.PING

def test_application_close_strips_trigger_field():
    # Even if a frame_type is provided, APPLICATION_CLOSE must not carry it
    cc = ConnectionCloseFrame(errno=0xdead, reason=b"app", frame_type=QuicFrameType.PING)
    qf = QuicFrame(QuicFrameType.APPLICATION_CLOSE, cc)
    assert qf.content.frame_type is None

def test_padding_cannot_have_content():
    with pytest.raises(ValueError):
        QuicFrame(QuicFrameType.PADDING, ConnectionCloseFrame(errno=0, reason=b"x", frame_type=None))

def test_iterating_frames():
    # Compose a stream of frames (e.g., PADDING + MAX_DATA + PADDING)
    data = b''.join([
        QuicFrame(frame_type=QuicFrameType.PADDING).encode(),
        QuicFrame(frame_type=QuicFrameType.MAX_DATA, content=MaxDataFrame(max_data=42)).encode(),
        QuicFrame(frame_type=QuicFrameType.PADDING).encode(),
    ])

    frames, consumed = parse_all_quic_frames(data + b'garbage')
    assert len(frames) == 3
    assert frames[1].frame_type == QuicFrameType.MAX_DATA
    assert consumed == 4

def test_datagram_no_length_roundtrip_simple():
    payload = b'hello world'
    qf = QuicFrame(QuicFrameType.DATAGRAM, DatagramFrame(datagram_data=payload))
    wire = qf.encode()

    decoded, used = QuicFrame.decode(wire)
    assert used == len(wire)
    assert decoded.frame_type == QuicFrameType.DATAGRAM
    assert isinstance(decoded.content, DatagramFrame)
    assert decoded.content.with_length is False
    assert decoded.content.datagram_data == payload

def test_datagram_with_length_roundtrip_simple():
    payload = b'abc123'
    qf = QuicFrame(QuicFrameType.DATAGRAM_WITH_LENGTH, DatagramFrame(datagram_data=payload, with_length=True))
    wire = qf.encode()

    decoded, used = QuicFrame.decode(wire)
    assert used == len(wire)
    assert decoded.frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH
    assert isinstance(decoded.content, DatagramFrame)
    assert decoded.content.with_length is True
    assert decoded.content.datagram_data == payload

def test_datagram_no_length_consumes_rest_of_packet():
    # Build: [DATAGRAM(no-length, b'xyz')] + [PADDING] → PADDING is consumed into datagram payload
    dgram = QuicFrame(QuicFrameType.DATAGRAM, DatagramFrame(datagram_data=b'xyz'))
    padding = QuicFrame(QuicFrameType.PADDING)
    wire = dgram.encode() + padding.encode()

    frames, consumed = parse_all_quic_frames(wire)
    assert consumed == len(wire)
    assert len(frames) == 1                            # no separate PADDING frame parsed
    d = frames[0]
    assert d.frame_type == QuicFrameType.DATAGRAM
    assert isinstance(d.content, DatagramFrame)
    # payload includes the trailing PADDING type byte (since no-length consumes rest)
    assert d.content.datagram_data.endswith(padding.encode())

def test_datagram_with_length_allows_following_frames():
    # Build: [DATAGRAM_WITH_LENGTH(len=3,'xyz')] + [PADDING]
    dgram = QuicFrame(QuicFrameType.DATAGRAM_WITH_LENGTH, DatagramFrame(datagram_data=b'xyz', with_length=True))
    padding = QuicFrame(QuicFrameType.PADDING)
    wire = dgram.encode() + padding.encode()

    frames, consumed = parse_all_quic_frames(wire)
    assert consumed == len(wire)
    assert len(frames) == 2
    assert frames[0].frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH
    assert isinstance(frames[0].content, DatagramFrame)
    assert frames[0].content.datagram_data == b'xyz'
    assert frames[1].frame_type == QuicFrameType.PADDING
