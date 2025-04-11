from dataclasses import dataclass, field
from enum import IntEnum
from inspect import isclass
from typing import Optional, List, ClassVar

from .crypto import decode_var_length_int
from .exceptions import QuicConnectionError, QuicErrorCode


# QUIC Frame
# : The payload of QUIC Packets, after removing packet protection, consists of a sequence of complete frames. Some
# Packet types (Version Negotiation, Stateless Reset, and Retry) do not contain Frames.
#
# The payload of a packet that contains frames MUST contain at least one frame, and MAY contain multiple frames and
# multiple frame types. An endpoint MUST treat receipt of a packet containing no frames as a connection error of type
# PROTOCOL_VIOLATION. Frames always fit within a single QUIC packet and cannot span multiple packets.
#
# An endpoint MUST treat the receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR.
#
# All frames are idempotent in this version of QUIC. That is, a valid frame does not cause undesirable side effects
# or errors when received more than once.

def encode_var_length_int(value: int) -> bytes:
    """
    Encode a variable length integer into a number of 1, 2, 4, or 8 bytes.

    :param value: integer value to be encoded
    :return: 1-8 bytes with the encoded value
    """
    if not (0 <= value < 2 ** 62):
        raise ValueError("QUIC variable-length integers must be in range [0, 2^62).")

    if value < 2 ** 6:  # 1-byte encoding: 00xxxxxx
        return bytes([value | 0b00000000])
    elif value < 2 ** 14:  # 2-byte encoding: 01xxxxxxxxxxxxxx
        value |= 0b01 << 14  # Set length bits
        return value.to_bytes(2, "big")
    elif value < 2 ** 30:  # 4-byte encoding: 10xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        value |= 0b10 << 30
        return value.to_bytes(4, "big")
    else:  # 8-byte encoding: 11...
        value |= 0b11 << 62
        return value.to_bytes(8, "big")

class QuicFrameType(IntEnum):
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    ACK_ECN = 0x03
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM_BASE = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    MAX_STREAMS_BIDI = 0x12
    MAX_STREAMS_UNI = 0x13
    DATA_BLOCKED = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED_BIDI = 0x16
    STREAMS_BLOCKED_UNI = 0x17
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    TRANSPORT_CLOSE = 0x1C
    APPLICATION_CLOSE = 0x1D
    HANDSHAKE_DONE = 0x1E
    # DATAGRAM = 0x30
    # DATAGRAM_WITH_LENGTH = 0x31

    def __str__(self):
        friendly_names = {
            self.PADDING: "Padding Frame",
            self.PING: "Ping Frame",
            self.ACK: "Acknowledgment (ACK) Frame",
            self.ACK_ECN: "ACK Frame with ECN",
            self.RESET_STREAM: "Reset Stream Frame",
            self.STOP_SENDING: "Stop Sending Frame",
            self.CRYPTO: "Crypto Frame",
            self.NEW_TOKEN: "New Token Frame",
            self.STREAM_BASE: "Stream Frame (Base Type)",
            self.MAX_DATA: "Max Data Frame",
            self.MAX_STREAM_DATA: "Max Stream Data Frame",
            self.MAX_STREAMS_BIDI: "Max Bidirectional Streams Frame",
            self.MAX_STREAMS_UNI: "Max Unidirectional Streams Frame",
            self.DATA_BLOCKED: "Data Blocked Frame",
            self.STREAM_DATA_BLOCKED: "Stream Data Blocked Frame",
            self.STREAMS_BLOCKED_BIDI: "Streams Blocked (Bidi) Frame",
            self.STREAMS_BLOCKED_UNI: "Streams Blocked (Uni) Frame",
            self.NEW_CONNECTION_ID: "New Connection ID Frame",
            self.RETIRE_CONNECTION_ID: "Retire Connection ID Frame",
            self.PATH_CHALLENGE: "Path Challenge Frame",
            self.PATH_RESPONSE: "Path Response Frame",
            self.TRANSPORT_CLOSE: "Transport Close Frame",
            self.APPLICATION_CLOSE: "Application Close Frame",
            self.HANDSHAKE_DONE: "Handshake Done Frame"
        }
        return friendly_names.get(self, f"Unknown Frame (0x{self.value:02x})")

NON_ACK_ELICITING_FRAME_TYPES = frozenset(
    [
        QuicFrameType.ACK,
        QuicFrameType.ACK_ECN,
        QuicFrameType.PADDING,
        QuicFrameType.TRANSPORT_CLOSE,
        QuicFrameType.APPLICATION_CLOSE,
    ]
)
NON_IN_FLIGHT_FRAME_TYPES = frozenset(
    [
        QuicFrameType.ACK,
        QuicFrameType.ACK_ECN,
        QuicFrameType.TRANSPORT_CLOSE,
        QuicFrameType.APPLICATION_CLOSE,
    ]
)
PROBING_FRAME_TYPES = frozenset(
    [
        QuicFrameType.PATH_CHALLENGE,
        QuicFrameType.PATH_RESPONSE,
        QuicFrameType.PADDING,
        QuicFrameType.NEW_CONNECTION_ID,
    ]
)

@dataclass
class FrameSubtype:
    def encode(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    def decode(cls, data: bytes) -> tuple["FrameSubtype", int]:
        raise NotImplementedError()

FRAME_TYPE_TO_CLASS = {}
def register_frame_type(frame_type: QuicFrameType):
    def wrapper(cls):
        FRAME_TYPE_TO_CLASS[frame_type] = cls
        return cls
    return wrapper

@dataclass
class QuicFrame:

    frame_type: QuicFrameType
    # Note:  To ensure simple and efficient implementations of frame parsing, a frame type MUST use the shortest
    #  possible encoding, which means 1 byte for QUIC VERSION_1 frame types.   An endpoint MAY treat the receipt of a
    #  frame type that uses a longer encoding than necessary as a connection error of type PROTOCOL_VIOLATION.

    content: Optional[FrameSubtype] = None

    def __post_init__(self):
        if self.frame_type in [QuicFrameType.PADDING, QuicFrameType.PING, QuicFrameType.HANDSHAKE_DONE]:
            if self.content:
                raise ValueError(f"QUIC {self.frame_type} cannot have content")

    def encode(self) -> bytes:
        var_int = encode_var_length_int(self.frame_type)
        assert len(var_int) == 1
        if not self.content:  # None or empty
            return var_int
        if self.frame_type is QuicFrameType.STREAM_BASE:
            return self.content.encode()  # flags for STREAM are embedded in first byte (frame type)
        return var_int + self.content.encode()

    @classmethod
    def decode(cls, data: bytes) -> tuple["QuicFrame", int]:
        # first byte contains always the type:
        var_int, _ = decode_var_length_int(data[0:1])

        # STREAM frames have flags embedded
        if var_int & 0b11111000 == QuicFrameType.STREAM_BASE:
            content, offset = StreamFrame.decode(data)
            return cls(QuicFrameType.STREAM_BASE, content=content), offset

        frame_type = QuicFrameType(var_int)  # propagate ValueError

        # Frames without content
        if frame_type in [QuicFrameType.PADDING, QuicFrameType.PING, QuicFrameType.HANDSHAKE_DONE]:
            return cls(frame_type), 1

        # Content-bearing frames: decode everything after first byte
        subtype_cls = FRAME_TYPE_TO_CLASS.get(frame_type)
        if subtype_cls is not None:
            # special cases: pass frame_type in
            if frame_type in (QuicFrameType.ACK, QuicFrameType.ACK_ECN):
                content, offset = subtype_cls.decode(data[1:], frame_type=frame_type)
            elif frame_type in (QuicFrameType.TRANSPORT_CLOSE, QuicFrameType.APPLICATION_CLOSE):
                content, offset = subtype_cls.decode(data[1:], is_transport=frame_type == QuicFrameType.TRANSPORT_CLOSE)
            else:
                content, offset = subtype_cls.decode(data[1:])
            return cls(frame_type, content=content), offset + 1

        raise NotImplementedError(f"QUIC frame type {frame_type} not implemented")

def iter_quic_frames(data: bytes):
    offset = 0
    while offset < len(data):
        try:
            frame, consumed = QuicFrame.decode(data[offset:])
        except ValueError:
            break  # ignore all ValueErrors and stop parsing
        offset += consumed
        # if frame.frame_type == QuicFrameType.PADDING:
        #     continue
        yield frame, consumed

def parse_all_quic_frames(data: bytes) -> tuple[list[QuicFrame], int]:
    frames = []
    total_consumed = 0

    for frame, consumed in iter_quic_frames(data):
        frames.append(frame)
        total_consumed += consumed

    return frames, total_consumed

### QUIC Frame subtypes with content below:

@dataclass
class ACKRange:
    gap: int
    ack_range_length: int

    def encode(self) -> bytes:
        return encode_var_length_int(self.gap) + encode_var_length_int(self.ack_range_length)

    @classmethod
    def decode(cls, data: bytes) -> tuple["ACKRange", int]:
        gap, offset = decode_var_length_int(data)
        ack_range_length, offset = decode_var_length_int(data[offset:], offset)
        return cls(gap, ack_range_length), offset

@dataclass
class ECNCounts:
    ect0: int
    ect1: int
    ce: int

    def encode(self) -> bytes:
        return (
            encode_var_length_int(self.ect0) +
            encode_var_length_int(self.ect1) +
            encode_var_length_int(self.ce)
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["ECNCounts", int]:
        ect0, offset = decode_var_length_int(data)
        ect1, offset = decode_var_length_int(data[offset:], offset)
        ce, offset = decode_var_length_int(data[offset:], offset)
        return cls(ect0, ect1, ce), offset

ACK_DELAY_EXPONENT = 3  # Used to scale ack_delay to/from encoded value

@register_frame_type(QuicFrameType.ACK)
@register_frame_type(QuicFrameType.ACK_ECN)
@dataclass
class ACKFrame(FrameSubtype):
    largest_ack: int
    ack_delay: int  # in microseconds
    first_ack_range: int
    ack_ranges: List[ACKRange] = field(default_factory=list)
    ecn_counts: Optional[ECNCounts] = None

    def __post_init__(self):
        # Ensure that ACK delay is greater or equal 8
        if self.ack_delay < 8:
            raise ValueError("ACK delay must be at least 8")

        # Ensure packet number math doesn't underflow
        if self.largest_ack < self.first_ack_range:
            raise QuicConnectionError(
                QuicErrorCode.FRAME_ENCODING_ERROR,
                "Invalid ACK frame: first_ack_range > largest_ack"
            )

        if len(self.ack_ranges) > 0:
            lowest_ack = self.largest_ack - self.first_ack_range
            for r in self.ack_ranges:
                if lowest_ack < r.gap + r.ack_range_length + 1:
                    raise QuicConnectionError(
                        QuicErrorCode.FRAME_ENCODING_ERROR,
                        "ACK range would underflow packet number space"
                    )
                lowest_ack -= r.gap + r.ack_range_length + 1

    @property
    def ack_range_count(self) -> int:
        return len(self.ack_ranges)

    def encode(self) -> bytes:
        encoded_ack_delay = self.ack_delay // (1 << ACK_DELAY_EXPONENT)
        ack_ranges_bytes = b''.join(r.encode() for r in self.ack_ranges)

        frame_bytes = (
            encode_var_length_int(self.largest_ack) +
            encode_var_length_int(encoded_ack_delay) +
            encode_var_length_int(self.ack_range_count) +
            encode_var_length_int(self.first_ack_range) +
            ack_ranges_bytes
        )

        if self.ecn_counts:
            frame_bytes += self.ecn_counts.encode()

        return frame_bytes

    @classmethod
    def decode(cls, data: bytes, frame_type: int = QuicFrameType.ACK) -> tuple["ACKFrame", int]:
        largest_ack, offset = decode_var_length_int(data)
        encoded_ack_delay, offset = decode_var_length_int(data[offset:], offset)
        ack_range_count, offset = decode_var_length_int(data[offset:], offset)
        first_ack_range, offset = decode_var_length_int(data[offset:], offset)

        ack_ranges = []
        for _ in range(ack_range_count):
            gap, offset = decode_var_length_int(data[offset:], offset)
            length, offset = decode_var_length_int(data[offset:], offset)
            ack_ranges.append(ACKRange(gap=gap, ack_range_length=length))

        ecn_counts = None
        ecn_offset = 0
        if frame_type == QuicFrameType.ACK_ECN:
            ecn_counts, ecn_offset = ECNCounts.decode(data[offset:])

        return cls(
            largest_ack=largest_ack,
            ack_delay=encoded_ack_delay * (1 << ACK_DELAY_EXPONENT),
            first_ack_range=first_ack_range,
            ack_ranges=ack_ranges,
            ecn_counts=ecn_counts
        ), offset + ecn_offset

@register_frame_type(QuicFrameType.RESET_STREAM)
@dataclass
class ResetStreamFrame(FrameSubtype):
    stream_id: int
    app_error: int
    final_size: int

    def encode(self) -> bytes:
        return (
            encode_var_length_int(self.stream_id) +
            encode_var_length_int(self.app_error) +
            encode_var_length_int(self.final_size)
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["ResetStreamFrame", int]:
        stream_id, offset = decode_var_length_int(data)
        app_error, offset = decode_var_length_int(data[offset:], offset)
        final_size, offset = decode_var_length_int(data[offset:], offset)
        return cls(stream_id, app_error, final_size), offset

@register_frame_type(QuicFrameType.STOP_SENDING)
@dataclass
class StopSendingFrame(FrameSubtype):
    stream_id: int
    app_error: int

    def encode(self) -> bytes:
        return (
            encode_var_length_int(self.stream_id) +
            encode_var_length_int(self.app_error)
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["StopSendingFrame", int]:
        stream_id, offset = decode_var_length_int(data)
        app_error, offset = decode_var_length_int(data[offset:], offset)
        return cls(stream_id, app_error), offset

@register_frame_type(QuicFrameType.CRYPTO)
@dataclass
class CryptoFrame(FrameSubtype):
    data_offset: int
    crypto_data: bytes = b''

    @property
    def data_length(self) -> int:
        return len(self.crypto_data)

    def encode(self) -> bytes:
        return (
                encode_var_length_int(self.data_offset) +
                encode_var_length_int(self.data_length) +
                self.crypto_data
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["CryptoFrame", int]:
        data_offset, offset = decode_var_length_int(data)
        data_length, offset = decode_var_length_int(data[offset:], offset)
        return cls(data_offset,
                   crypto_data=data[offset:offset + data_length]), offset + data_length

@register_frame_type(QuicFrameType.NEW_TOKEN)
@dataclass
class NewTokenFrame(FrameSubtype):
    token: bytes

    @property
    def token_length(self) -> int:
        return len(self.token)

    def encode(self) -> bytes:
        return encode_var_length_int(self.token_length) + self.token

    @classmethod
    def decode(cls, data: bytes) -> tuple["NewTokenFrame", int]:
        token_length, offset = decode_var_length_int(data)
        return cls(data[offset:offset + token_length:]), offset + token_length

#@register_frame_type(QuicFrameType.STREAM_BASE)  # Used for mapping base frame type
@dataclass
class StreamFrame(FrameSubtype):
    stream_id: int
    offset: int = 0
    fin: bool = False
    data: bytes = b''
    include_length: bool = True  # In practice, this is almost always true

    def encode(self) -> bytes:
        flags = QuicFrameType.STREAM_BASE  #0x08  # STREAM base

        if self.offset > 0:
            flags |= 0x04
        if self.include_length:
            flags |= 0x02
        if self.fin:
            flags |= 0x01

        buf = bytearray()
        buf.append(flags)
        buf += encode_var_length_int(self.stream_id)
        if self.offset > 0:
            buf += encode_var_length_int(self.offset)
        if self.include_length:
            buf += encode_var_length_int(len(self.data))
        buf += self.data
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> tuple["StreamFrame", int]:
        frame_type = data[0]
        assert frame_type & 0b11111000 == 0x08  # Must be a STREAM frame

        offset = 1
        stream_id, offset = decode_var_length_int(data[offset:], offset)

        # detect flags
        has_offset = (frame_type & 0x04) != 0
        has_length = (frame_type & 0x02) != 0
        has_fin = (frame_type & 0x01) != 0

        stream_offset = 0
        if has_offset:
            stream_offset, offset = decode_var_length_int(data[offset:], offset)
        if has_length:
            length, offset = decode_var_length_int(data[offset:], offset)
            stream_data = data[offset:offset + length]
            offset += length
        else:
            stream_data = data[offset:]
            offset = len(data)

        return cls(
            stream_id=stream_id,
            offset=stream_offset,
            fin=has_fin,
            data=stream_data,
            include_length=has_length
        ), offset

# more generic way of handling frames that contain a single, variable-length integer field:
@dataclass
class SingleVarIntNamedFrame(FrameSubtype):
    value: int
    _field_name: ClassVar[str] = "value"

    def __init__(self, **kwargs):
        if self._field_name not in kwargs:
            raise ValueError(f"Missing required field: {self._field_name}")
        object.__setattr__(self, self._field_name, kwargs[self._field_name])
        object.__setattr__(self, "value", kwargs[self._field_name])

    def encode(self) -> bytes:
        return encode_var_length_int(getattr(self, self._field_name))

    @classmethod
    def decode(cls, data: bytes) -> tuple["SingleVarIntNamedFrame", int]:
        value, offset = decode_var_length_int(data)
        return cls(**{cls._field_name: value}), offset

@register_frame_type(QuicFrameType.MAX_DATA)
class MaxDataFrame(SingleVarIntNamedFrame):
    _field_name = "max_data"

@register_frame_type(QuicFrameType.MAX_STREAM_DATA)
@dataclass
class MaxStreamData(FrameSubtype):
    stream_id: int
    max_stream_data: int

    def encode(self) -> bytes:
        return encode_var_length_int(self.stream_id) + encode_var_length_int(self.max_stream_data)

    @classmethod
    def decode(cls, data: bytes) -> tuple["MaxStreamData", int]:
        stream_id, offset = decode_var_length_int(data)
        max_stream_data, offset = decode_var_length_int(data[offset:], offset)
        return cls(stream_id, max_stream_data), offset

@register_frame_type(QuicFrameType.MAX_STREAMS_BIDI)
class MaxStreamsBidiFrame(SingleVarIntNamedFrame):
    _field_name = "max_streams"

@register_frame_type(QuicFrameType.MAX_STREAMS_UNI)
class MaxStreamsUniFrame(SingleVarIntNamedFrame):
    _field_name = "max_streams"

@register_frame_type(QuicFrameType.DATA_BLOCKED)
class DataBlockedFrame(SingleVarIntNamedFrame):
    _field_name = "data_limit"

@register_frame_type(QuicFrameType.STREAM_DATA_BLOCKED)
@dataclass
class StreamDataBlockedFrame(FrameSubtype):
    stream_id: int
    max_stream_data: int

    def encode(self) -> bytes:
        return (
            encode_var_length_int(self.stream_id) +
            encode_var_length_int(self.max_stream_data)
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["StreamDataBlockedFrame", int]:
        stream_id, offset = decode_var_length_int(data)
        max_stream_data, offset = decode_var_length_int(data[offset:], offset)
        return cls(stream_id, max_stream_data), offset

@register_frame_type(QuicFrameType.STREAMS_BLOCKED_BIDI)
class StreamsBlockedBidiFrame(SingleVarIntNamedFrame):
    _field_name = "limit"

@register_frame_type(QuicFrameType.STREAMS_BLOCKED_UNI)
class StreamsBlockedUniFrame(SingleVarIntNamedFrame):
    _field_name = "limit"

@register_frame_type(QuicFrameType.NEW_CONNECTION_ID)
@dataclass
class NewConnectionIDFrame(FrameSubtype):
    seq_no: int
    retire_prior_to: int
    connection_id: bytes
    reset_token: bytes

    def __post_init__(self):
        if not self.connection_id:
            raise ValueError(f"NEW_CONNECTION_ID frame must include non-empty connection ID")
        if len(self.connection_id) > 20:
            raise ValueError(f"NEW_CONNECTION_ID frame with too long connection ID")
        if len(self.reset_token) != 16:
            raise ValueError(f"NEW_CONNECTION_ID frame reset token must be exactly 16 bytes (= 128 bits)")

    def encode(self) -> bytes:
        length = encode_var_length_int(len(self.connection_id))
        assert len(length) == 1
        return (
                encode_var_length_int(self.seq_no) +
                encode_var_length_int(self.retire_prior_to) +
                length +
                self.connection_id +
                self.reset_token)

    @classmethod
    def decode(cls, data: bytes) -> tuple["NewConnectionIDFrame", int]:
        seq_no, offset = decode_var_length_int(data)
        retire_prior_to, offset = decode_var_length_int(data[offset:], offset)
        length = int.from_bytes(data[offset:offset + 1])
        offset += 1
        return cls(seq_no,
                   retire_prior_to,
                   data[offset:offset + length],
                   data[offset + length:offset + length + 16]), offset + length + 16

@register_frame_type(QuicFrameType.RETIRE_CONNECTION_ID)
class RetireConnectionIDFrame(SingleVarIntNamedFrame):
    _field_name = "sequence_number"

@register_frame_type(QuicFrameType.PATH_CHALLENGE)
@register_frame_type(QuicFrameType.PATH_RESPONSE)
@dataclass
class PathChallengeResponseFrame(FrameSubtype):
    data: bytes

    def __post_init__(self):
        if len(self.data) != 8:
            raise ValueError("Path Challenge and Response must be 8 bytes")

    def encode(self) -> bytes:
        return self.data

    @classmethod
    def decode(cls, data: bytes) -> tuple["PathChallengeResponseFrame", int]:
        return cls(data[:8]), 8

@register_frame_type(QuicFrameType.TRANSPORT_CLOSE)
@register_frame_type(QuicFrameType.APPLICATION_CLOSE)
@dataclass
class ConnectionCloseFrame(FrameSubtype):
    errno: int
    reason: bytes
    frame_type: Optional[int] = None

    def encode(self) -> bytes:
        return (
                encode_var_length_int(self.errno) +
                (encode_var_length_int(self.frame_type) if self.frame_type is not None else b'') +
                encode_var_length_int(len(self.reason)) +
                self.reason
        )

    @classmethod
    def decode(cls, data: bytes, is_transport: bool = True) -> tuple["ConnectionCloseFrame", int]:
        errno, offset = decode_var_length_int(data)
        frame_type = None
        if is_transport:
            frame_type, offset = decode_var_length_int(data[offset:], offset)
        length, offset = decode_var_length_int(data[offset:], offset)
        return cls(errno, data[offset:offset + length], frame_type), offset + length
