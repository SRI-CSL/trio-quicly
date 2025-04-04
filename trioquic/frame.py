from dataclasses import dataclass, field
from enum import IntEnum
from inspect import isclass
from typing import Optional, List

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
        if self.frame_type in [QuicFrameType.PADDING, QuicFrameType.PING]:
            if self.content:
                raise ValueError(f"QUIC {self.frame_type} cannot have content")

    def encode(self) -> bytes:
        var_int = encode_var_length_int(self.frame_type)
        assert len(var_int) == 1
        if not self.content:  # None or empty
            return var_int
        return var_int + self.content.encode()

    @classmethod
    def decode(cls, data: bytes) -> tuple["QuicFrame", int]:
        # first byte contains always the type:
        var_int, _ = decode_var_length_int(data[0:1])
        frame_type = QuicFrameType(var_int)  # propagate ValueError

        # Frames without content
        if frame_type in [QuicFrameType.PADDING, QuicFrameType.PING]:
            return cls(frame_type), 1

        # Content-bearing frames
        subtype_cls = FRAME_TYPE_TO_CLASS.get(frame_type)
        if subtype_cls is not None:
            # ACK/ACK_ECN special case: pass frame_type in
            if frame_type in (QuicFrameType.ACK, QuicFrameType.ACK_ECN):
                content, offset = subtype_cls.decode(data[1:], frame_type=frame_type)
            else:
                content, offset = subtype_cls.decode(data[1:])
            return cls(frame_type, content=content), offset + 1

        raise NotImplementedError(f"QUIC frame type {frame_type} not implemented")

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
                encode_var_length_int(len(self.crypto_data)) +
                self.crypto_data
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["CryptoFrame", int]:
        data_offset, offset = decode_var_length_int(data)
        data_length, offset = decode_var_length_int(data[offset:], offset)
        return cls(data_offset,
                   crypto_data=data[offset:offset + data_length]), offset + data_length

# TODO: continue with https://datatracker.ietf.org/doc/html/rfc9000#name-new_token-frames