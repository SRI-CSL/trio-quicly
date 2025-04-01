from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from .crypto import decode_var_length_int


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
    def decode(cls, data: bytes) -> "FrameSubtype":
        raise NotImplementedError()

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
    def decode(cls, data: bytes) -> "QuicFrame":
        # first byte contains always the type:
        var_int, _ = decode_var_length_int(data[0:1])
        frame_type = QuicFrameType(var_int)  # propagate ValueError
        if frame_type in [QuicFrameType.PADDING, QuicFrameType.PING]:
            return cls(frame_type)
        # TODO: handle other frame types here...
        raise NotImplementedError()

@dataclass
class ACKFrame(FrameSubtype):
    largest_ack: int
    ack_delay: int
    ack_range_count: int
    first_ack_range: int
#   ACK Range (..) ...,
#   [ECN Counts (..)],

    def encode(self) -> bytes:
        pass

    @classmethod
    def decode(cls, data: bytes) -> "ACKFrame":
        pass