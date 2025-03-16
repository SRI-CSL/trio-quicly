import math
import struct
from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
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

@dataclass
class QuicPacket:

    is_long_header: bool = field(init=False)  # defines first bit in first byte

    packet_type: QuicPacketType = field(init=False)  #  not encoded for `VERSION_NEGOTIATION` and `ONE_RTT` packets

    destination_cid: bytes  # destination connection ID (0--20 Bytes)

    packet_number_length: Optional[int] = field(init=False)  # 2 bits = 0..3 values.
    # To be derived post_init from packet_number!
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.

    packet_number: Optional[int] = field(init=False)  # The packet number (1..4 Bytes).
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.

    payload: Optional[bytes] = field(init=False)  # The packet payload (1.. Bytes).
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.

    reserved_bits: int = field(default=0, init=False)  # 2 bits = values 0..3.
    # Only present in `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, and `ONE_RTT` packets.
    # Must be 0 prior to protection, otherwise, endpoint receiving and having removed both packet and header
    # protection should treat this as connection error of type PROTOCOL_VIOLATION.

    def encode_first_byte(self) -> int:
        # The struct module provides a way to convert data to/from C structs (or network data).
        raise NotImplementedError()

    def __post_init__(self):
        # derive values and sanity checks
        if self.packet_number is not None:
            # TODO: research whether packet numbers also use var int encoding!
            self.packet_number_length = math.ceil(self.packet_number.bit_length() / 8)
            assert 1 <= self.packet_number_length <= 4

@dataclass
class LongHeaderPacket(QuicPacket):

    is_long_header: bool = field(default=True, init=False)
    packet_type: QuicPacketType = field(init=True)  #  not encoded for `VERSION_NEGOTIATION` packets

    version: int = field(init=False)

    source_cid: bytes = None  # source connection ID (0..20 Bytes)

    supported_versions: List[int] = None  # Supported protocol versions. Only present in `VERSION_NEGOTIATION` packets.

    token: bytes = None  # The address verification token. Only present in `INITIAL` and `RETRY` packets.

    integrity_tag: bytes = None  # The retry integrity tag. Only present in `RETRY` packets.

    # optional values
    packet_number = None
    payload = None

    def __post_init__(self):
        self.version = QuicProtocolVersion.NEGOTIATION if self.packet_type == QuicPacketType.VERSION_NEGOTIATION \
            else QuicProtocolVersion.VERSION_1

    def encode_first_byte(self) -> int:
        if self.packet_type == QuicPacketType.VERSION_NEGOTIATION:
            return PACKET_LONG_HEADER
        else:
            assert self.packet_type != QuicPacketType.ONE_RTT
            raise NotImplementedError()  # TODO: implement!
            # if self.packet_type == QuicPacketType.RETRY:
            #     bits = 0x0000
            # else:
            #     bits = self.reserved_bits << 2 | self.packet_number_length
            # return (
            #         PACKET_LONG_HEADER
            #         | PACKET_FIXED_BIT
            #         | self.packet_type << 4
            #         | bits
            # )

@dataclass
class ShortHeaderPacket(QuicPacket):

    is_long_header: bool = field(default=False, init=False)
    packet_type: QuicPacketType = field(default=QuicPacketType.ONE_RTT, init=False)

    spin_bit: bool = False
    key_phase: bool = True
    packet_number: int = field(init=True)
    payload: bytes = field(init=True)

    def encode_first_byte(self) -> int:
        assert self.reserved_bits.bit_length() <= 2
        assert self.packet_number_length.bit_length() <= 2
        return (
            (self.is_long_header << 7)  # first bit should be 0
            | (1 << 6)                  # second bit is FIXED BIT
            | (self.spin_bit << 5)
            | (self.reserved_bits << 3)
            | (self.key_phase << 2)
            | self.packet_number_length
        )

def create_quic_packet(packet_type: QuicPacketType, destination_cid: bytes, **kwargs) -> QuicPacket:
    if packet_type == QuicPacketType.ONE_RTT:
        # TODO: slice kwargs to include: spin_bit, key_phase, packet_number, payload
        return ShortHeaderPacket(destination_cid=destination_cid, **kwargs)
    elif packet_type == QuicPacketType.VERSION_NEGOTIATION:
        return LongHeaderPacket(packet_type=QuicPacketType.VERSION_NEGOTIATION,
                                destination_cid=destination_cid)
    # TODO: slice kwargs to include: packet_type, packet_number, etc...
    return LongHeaderPacket(destination_cid=destination_cid, **kwargs)
