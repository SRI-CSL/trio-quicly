import math
import struct
from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
from importlib.metadata import requires
from typing import *

MAX_UDP_PACKET_SIZE = 65527

# QUIC Packet
# : QUIC Endpoints communicate by exchanging Packets. Packets have confidentiality and integrity protection. QUIC Packets
# are complete processable units of QUIC that can be encapsulated in a UDP datagram. One or more QUIC Packets can be
# encapsulated in a single UDP datagram, which is in turn encapsulated in an IP packet.

CLIENT_VERSION = bytes.fromhex("03 03")  # always indicates TLS 1.2 to allow passing through middle boxes
PACKET_LONG_HEADER = 0x80
PACKET_FIXED_BIT = 0x40
PACKET_SPIN_BIT = 0x20

def get_spin_bit(first_byte: int) -> bool:
    return bool(first_byte & PACKET_SPIN_BIT)

def is_long_header(first_byte: int) -> bool:
    return bool(first_byte & PACKET_LONG_HEADER)

def encode_var_length_int(value: int) -> bytes:
    """
    Encode a variable length integer from a stream of bytes.

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

class QuicProtocolVersion(IntEnum):
    NEGOTIATION = 0
    VERSION_1 = 0x00000001
    # VERSION_2 = 0x6B3343CF

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
    DATAGRAM = 0x30
    DATAGRAM_WITH_LENGTH = 0x31

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
class QuicFrame:
    content: bytes

class QuicPacketType(IntEnum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    VERSION_NEGOTIATION = 4
    ONE_RTT = 5

    def __str__(self):
        return {
            QuicPacketType.INITIAL: "Initial Packet",
            QuicPacketType.ZERO_RTT: "0-RTT Packet",
            QuicPacketType.HANDSHAKE: "Handshake Packet",
            QuicPacketType.RETRY: "Retry Packet",
            QuicPacketType.VERSION_NEGOTIATION: "Version Negotiation Packet",
            QuicPacketType.ONE_RTT: "1-RTT Packet",
        }[self]

@dataclass
class QuicPacket:

    is_long_header: bool = field(init=False)  # defines first bit in first byte

    packet_type: QuicPacketType = field(init=False)  #  not encoded for `VERSION_NEGOTIATION` and `ONE_RTT` packets

    destination_cid: bytes  # destination connection ID (0--20 Bytes)

    packet_number_length: int = field(default=1, init=False)  # 2 bits + 1 = 1..4 values.
    # To be derived post_init from packet_number!
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.

    packet_number: Optional[int] = field(default=None, init=False)  # The packet number (1..4 Bytes).
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.

    payload: Optional[bytes] = field(default=None, init=False)  # The packet payload (1.. Bytes).
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.

    reserved_bits: int = field(default=0, init=False)  # 2 bits = values 0..3.
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.
    # Must be 0 prior to protection, otherwise, endpoint receiving and having removed both packet and header
    # protection should treat this as connection error of type PROTOCOL_VIOLATION.

    def encode_first_byte(self) -> int:
        raise NotImplementedError()

    def encode_all_bytes(self) -> bytes:
        # The struct module provides a way to convert data to/from C structs (or network data).
        raise NotImplementedError()

    def __post_init__(self):
        # derive values and sanity checks
        if self.packet_number is not None:
            # TODO: research whether packet numbers also use var int encoding!
            self.packet_number_length = math.ceil(self.packet_number.bit_length() / 8)
            assert 1 <= self.packet_number_length <= 4
        assert self.reserved_bits.bit_length() <= 2

@dataclass
class LongHeaderPacket(QuicPacket):

    is_long_header: bool = field(default=True, init=False)
    packet_type: QuicPacketType = field(init=True)

    version: int = field(default=QuicProtocolVersion.VERSION_1, init=False)

    source_cid: bytes = None  # source connection ID (0..20 Bytes)

    token: bytes = None  # The address verification token. Only present in `INITIAL` and `RETRY` packets.

    integrity_tag: bytes = None  # The retry integrity tag. Only present in `RETRY` packets.

    packet_number: Optional[int] = None  # Not used for `RETRY` packets
    payload: Optional[bytes] = None  # Must contain at least 1 byte for all but `RETRY` packets

    def __post_init__(self):
        super().__post_init__()
        assert self.source_cid is not None
        if self.packet_type not in {QuicPacketType.RETRY, QuicPacketType.VERSION_NEGOTIATION}:
            assert self.packet_number is not None
            assert self.payload is not None
        elif self.packet_type is QuicPacketType.RETRY:
            assert self.integrity_tag is not None
            assert len(self.integrity_tag) == 16
            assert self.token is not None

    def encode_first_byte(self) -> int:
        assert self.packet_type not in {QuicPacketType.VERSION_NEGOTIATION, QuicPacketType.ONE_RTT}
        assert self.packet_type.bit_length() <= 2
        first_four_bits =  (
            (self.is_long_header << 3)  # first bit should be 1
            | (1 << 2)                  # second bit is FIXED BIT
            | self.packet_type
        )
        if self.packet_type != QuicPacketType.RETRY:
            assert self.reserved_bits.bit_length() <= 2
            assert (self.packet_number_length - 1).bit_length() <= 2
            return first_four_bits << 4 | (self.reserved_bits << 2) | (self.packet_number_length - 1)
        else:
            return first_four_bits << 4 | 0b0000  # bits 5..8 are unused for `RETRY` packets

    def encode_all_bytes(self) -> bytes:
        long_packed_header = struct.pack(
            f"!BLB{len(self.destination_cid)}sB{len(self.source_cid)}s",
            self.encode_first_byte(),
            self.version,
            len(self.destination_cid),
            self.destination_cid,
            len(self.source_cid),
            self.source_cid,
        )
        if self.packet_type == QuicPacketType.INITIAL:
            token_length = len(self.token) if self.token is not None else 0
            token_length_encoded = encode_var_length_int(token_length)
            prefix = long_packed_header \
                + struct.pack(
                    f"!{len(token_length_encoded)}s",
                    token_length_encoded)
            if token_length > 0:
                prefix += self.token
            length_encoded = encode_var_length_int(self.packet_number_length + len(self.payload))
            return prefix \
                + struct.pack(
                    f"{len(length_encoded)}s{self.packet_number_length}s",
                    length_encoded,
                    self.packet_number.to_bytes(self.packet_number_length)) \
                + self.payload
        elif self.packet_type in {QuicPacketType.ZERO_RTT, QuicPacketType.HANDSHAKE}:
            length_encoded = encode_var_length_int(self.packet_number_length + len(self.payload))
            return long_packed_header \
                + struct.pack(
                    f"!{len(length_encoded)}s{self.packet_number_length}s",
                    length_encoded,
                    self.packet_number.to_bytes(self.packet_number_length)) \
                + self.payload
        elif self.packet_type == QuicPacketType.RETRY:
            return long_packed_header \
                + self.token \
                + self.integrity_tag
        raise RuntimeError(f"Cannot encode packet type: {self.packet_type}")

@dataclass
class VersionNegotiationPacket(LongHeaderPacket):

    packet_type: QuicPacketType = field(default=QuicPacketType.VERSION_NEGOTIATION, init=False)
    version: int = field(default=QuicProtocolVersion.NEGOTIATION, init=False)
    packet_number: Optional[int] = field(default=None, init=False)  # not used for `VERSION_NEGOTIATION` packets
    supported_versions: List[int] = field(default_factory=list)  # Supported protocol versions.
                                                                 # Only present in `VERSION_NEGOTIATION` packets.

    def encode_first_byte(self) -> int:
        assert self.packet_type == QuicPacketType.VERSION_NEGOTIATION
        return PACKET_LONG_HEADER  # bits 2..8 are unused

    def encode_all_bytes(self) -> bytes:
        return struct.pack(
            f"!BLB{len(self.destination_cid)}sB{len(self.source_cid)}s{len(self.supported_versions)}L",
            self.encode_first_byte(),
            self.version,
            len(self.destination_cid),
            self.destination_cid,
            len(self.source_cid),
            self.source_cid,
            *self.supported_versions
        )

@dataclass
class ShortHeaderPacket(QuicPacket):

    is_long_header: bool = field(default=False, init=False)
    packet_type: QuicPacketType = field(default=QuicPacketType.ONE_RTT, init=False)

    spin_bit: bool = False
    key_phase: bool = True
    packet_number: int = field(init=True)
    payload: bytes = field(init=True)

    def __post_init__(self):
        super().__post_init__()
        assert self.payload is not None and len(self.payload) > 0

    def encode_first_byte(self) -> int:
        assert self.reserved_bits.bit_length() <= 2
        assert (self.packet_number_length - 1).bit_length() <= 2
        return (
            (self.is_long_header << 7)  # first bit should be 0
            | (1 << 6)                  # second bit is FIXED BIT
            | (self.spin_bit << 5)
            | (self.reserved_bits << 3)
            | (self.key_phase << 2)
            | (self.packet_number_length - 1)
        )

    def encode_all_bytes(self) -> bytes:
        packed_header = struct.pack(f"!B{len(self.destination_cid)}s{self.packet_number_length}s",
                                self.encode_first_byte(),
                                    self.destination_cid,
                                    self.packet_number.to_bytes(self.packet_number_length))
        return packed_header + self.payload

def create_quic_packet(packet_type: QuicPacketType, destination_cid: bytes, **kwargs) -> QuicPacket:
    if packet_type == QuicPacketType.ONE_RTT:
        required_keys = {"spin_bit", "key_phase", "packet_number", "payload"}
        if not required_keys.issubset(kwargs):
            raise ValueError(f"Missing required keyword arguments for {packet_type}: {required_keys - kwargs.keys()}")
        return ShortHeaderPacket(destination_cid=destination_cid, **kwargs)
    if "source_cid" not in kwargs:
        raise ValueError(f"Missing required keyword argument 'source_cid' for {packet_type}")
    elif packet_type == QuicPacketType.VERSION_NEGOTIATION:
        return VersionNegotiationPacket(destination_cid=destination_cid, **kwargs)
    # TODO: slice kwargs to include: packet_number, etc...
    # required_keys = {"supported_versions"}
    # if not required_keys.issubset(kwargs):
    #     raise ValueError(f"Missing required keyword arguments for {packet_type}: {required_keys - kwargs.keys()}")
    return LongHeaderPacket(packet_type=packet_type, destination_cid=destination_cid, **kwargs)
