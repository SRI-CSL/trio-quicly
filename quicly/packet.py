#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

from dataclasses import dataclass, field
from enum import IntEnum
import math
import secrets
import struct
from typing import *

from .exceptions import QuicProtocolViolation
from .frame import encode_var_length_int, decode_var_length_int, QuicFrame, parse_all_quic_frames, \
    NON_ACK_ELICITING_FRAME_TYPES, QuicFrameType

MAX_UDP_PACKET_SIZE = 65527  # TODO: Linda: move into configuration.py?!? or utils.py? or endpoint.py?

# QUIC Packet : QUIC Endpoints communicate by exchanging Packets. QUIC Packets are complete processable units of QUIC
# that can be encapsulated in a UDP datagram. One or more QUIC Packets can be encapsulated in a single UDP datagram,
# which is in turn encapsulated in an IP packet.

PACKET_LONG_HEADER = 0x80

def is_long_header(first_byte: int) -> bool:
    return bool(first_byte & PACKET_LONG_HEADER)

def get_connection_id(data: bytes) -> tuple[bytes, int]:
    cid_length = int.from_bytes(data[0:1], "big") # first byte has length information
    cid_bytes = data[1:cid_length+1]
    return cid_bytes, cid_length + 1

class QuicProtocolVersion(IntEnum):
    NEGOTIATION = 0
    VERSION_1 = 0x00000001
    VERSION_2 = 0x6b3343cf
    QUICLY = 0x51554c59  # "QULY": Easy to read in Wireshark. Won’t collide with IETF or grease values.

class QuicPacketType(IntEnum):
    INITIAL = 0
    ONE_RTT = 5

    def __str__(self):
        return {
            QuicPacketType.INITIAL: "initial",
            QuicPacketType.ONE_RTT: "1RTT",
        }[self]

@dataclass
class QuicPacket:

    is_long_header: bool = field(init=False)  # defines first bit in first byte

    packet_type: QuicPacketType = field(init=False)  #  not encoded for `ONE_RTT` packets

    destination_cid: bytes  # destination connection ID (0--20 Bytes)

    packet_number_length: int = field(default=1, init=False)  # 2 bits + 1 = 1..4 values.
    # To be derived post_init from packet_number!
    # Only present in `INITIAL` and `ONE_RTT` packets.

    packet_number: Optional[int] = field(default=None, init=False)  # The packet number (1..4 Bytes).
    # Only present in `INITIAL` and `ONE_RTT` packets.

    payload: Optional[List[QuicFrame]] = field(default=None, init=False)  # The packet payload (1.. Bytes).
    # Only present in `INITIAL` and `ONE_RTT` packets.

    reserved_bits: int = field(default=0, init=False)  # 2 bits = values 0..3.
    # Only present in `INITIAL` and `ONE_RTT` packets.
    # Must be 0 prior to protection, otherwise, endpoint receiving and having removed both packet and header
    # protection should treat this as connection error of type PROTOCOL_VIOLATION.
    # In QUIC-LY (without protection), these MUST always be 0.

    def encode_first_byte(self) -> int:
        raise NotImplementedError()

    def encode_all_bytes(self) -> bytes:
        # The struct module provides a way to convert data to/from C structs (or network data).
        raise NotImplementedError()

    @classmethod
    def decode_all_bytes(cls, data: bytes) -> tuple["QuicPacket", int]:
        raise NotImplementedError()

    def __post_init__(self):
        # derive values and sanity checks
        if self.packet_number is not None:
            # packet number is at least 1 byte long:
            self.packet_number_length = max(math.ceil(self.packet_number.bit_length() / 8), 1)
            assert 1 <= self.packet_number_length <= 4
        assert self.reserved_bits.bit_length() <= 2

    def is_ack_eliciting(self) -> bool:
        # Packets that contain at least one ack-eliciting frame are called ack-eliciting packets.
        return any(f.frame_type not in NON_ACK_ELICITING_FRAME_TYPES for f in self.payload)

    def is_closing(self) -> bool:
        return any(f.frame_type in [QuicFrameType.TRANSPORT_CLOSE, QuicFrameType.APPLICATION_CLOSE]
                   for f in self.payload)

@dataclass
class LongHeaderPacket(QuicPacket):

    # fixed values (since QUIC-LY only has INITIAL long header packets):
    is_long_header: bool = field(default=True, init=False)
    packet_type: QuicPacketType = field(default=QuicPacketType.INITIAL, init=False)  # QUIC-LY only has INITIAL type
    version: int = field(default=QuicProtocolVersion.QUICLY, init=False)

    source_cid: bytes = None  # source connection ID (0..20 Bytes)
    packet_number: int = None
    payload: List[QuicFrame] = None  # Must contain at least 1 byte

    def __post_init__(self):
        super().__post_init__()
        assert self.source_cid is not None

    def encode_first_byte(self) -> int:
        assert self.packet_type == QuicPacketType.INITIAL
        assert self.packet_type.bit_length() <= 2
        first_four_bits =  (
            (self.is_long_header << 3)  # first bit should be 1
            | (1 << 2)                  # second bit is FIXED BIT
            | self.packet_type
        )
        assert self.reserved_bits == 0  # in QUIC-LY only
        return first_four_bits << 4 | (self.reserved_bits << 2) | (self.packet_number_length - 1)

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
        payload_bytes = b''.join(p.encode() for p in self.payload)
        token_length = 0
        token_length_encoded = encode_var_length_int(token_length)
        prefix = long_packed_header \
                 + struct.pack(
            f"!{len(token_length_encoded)}s",
            token_length_encoded)
        length_encoded = encode_var_length_int(self.packet_number_length + len(payload_bytes))
        return prefix \
            + struct.pack(
                f"{len(length_encoded)}s{self.packet_number_length}s",
                length_encoded,
                self.packet_number.to_bytes(self.packet_number_length)) \
            + payload_bytes

    @classmethod
    def decode_all_bytes(cls, data: bytes) -> tuple["LongHeaderPacket", int]:
        pkt_type_n = (data[0] & 0b00110000) >> 4  # Bits 3–4

        if pkt_type_n != 0:
            raise ValueError(f"Packet type number {pkt_type_n} is not supported in QUIC-LY protocol")
        packet_type = QuicPacketType(pkt_type_n)

        assert int.from_bytes(data[1:5]) == QuicProtocolVersion.QUICLY
        dst_cid, offset = get_connection_id(data[5:])
        offset += 5
        src_cid, offset1 = get_connection_id(data[offset:])
        offset += offset1

        assert packet_type == QuicPacketType.INITIAL
        # parse lower 4-bits of first byte:
        reserved_bits = (data[0] & 0b00001100) >> 2  # Bits 5-6
        if not reserved_bits == 0:
            raise QuicProtocolViolation(f"{packet_type} must have 0b00 for reserved bits in long header")
        packet_number_length = (data[0] & 0b00000011) + 1  # Bits 7-8 but add 1 to map to values 1..4

        token_length, offset1 = decode_var_length_int(data[offset:])
        assert token_length == 0  # QUIC-LY is not using tokens
        offset += offset1
        length, offset1 = decode_var_length_int(data[offset:])
        offset += offset1
        frames, consumed = parse_all_quic_frames(data[offset+packet_number_length:offset+length]) # length includes packet number length and payload
        assert consumed == length - packet_number_length
        return LongHeaderPacket(destination_cid=dst_cid, source_cid=src_cid,
                                packet_number=int.from_bytes(data[offset:offset+packet_number_length]),
                                payload=frames), offset + length

@dataclass
class ShortHeaderPacket(QuicPacket):

    is_long_header: bool = field(default=False, init=False)
    packet_type: QuicPacketType = field(default=QuicPacketType.ONE_RTT, init=False)

    # When the spin bit is disabled, endpoints MAY set the spin bit to any value and MUST ignore any incoming value.
    # It is RECOMMENDED that endpoints set the spin bit to a random value either chosen independently for each packet
    # or chosen independently for each connection ID.
    spin_bit: bool = field(default_factory=lambda: bool(secrets.randbits(1)))
    # Not used in QUIC-LY: ignore and set to False (0) by default:
    key_phase: bool = False
    packet_number: int = field(init=True)
    payload: List[QuicFrame] = field(init=True, default_factory=list)

    def __post_init__(self):
        super().__post_init__()
        # assert self.payload is not None and len(self.payload) > 0

    def encode_first_byte(self) -> int:
        assert self.reserved_bits.bit_length() <= 2
        assert self.reserved_bits == 0  # in QUIC-LY only
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
        payload_bytes = b''.join(p.encode() for p in self.payload)
        return packed_header + payload_bytes

    @classmethod
    def decode_all_bytes(cls, data: bytes, **kwargs) -> tuple["ShortHeaderPacket", int]:
        if len(data) < 3:
            raise ValueError("1-RTT packet too short, must have at least 3 bytes")

        first_two_bits_set = (data[0] & 0b11000000) == 0b01000000
        if not first_two_bits_set:
            raise ValueError("1-RTT packet does not match expected format for first 2 bits")

        spin_bit = bool((data[0] & 0b00100000) >> 5)  # Bit 3 (from MSB)
        reserved_bits = (data[0] & 0b00011000) >> 3  # Bits 4-5
        key_phase = bool((data[0] & 0b00000100) >> 2)  # Bit 6
        packet_number_length = (data[0] & 0b00000011) + 1  # Bits 7-8 but add 1 to map to values 1..4

        if not reserved_bits == 0:
            raise QuicProtocolViolation("1-RTT packet must have 0b00 for reserved bits in short header")

        dest_cid = kwargs.pop('destination_cid', None)
        if dest_cid is None:
            raise ValueError("1-RTT packet required 'destination_cid' argument with destination connection ID")
        if not isinstance(dest_cid, bytes):
            raise TypeError(f"'destination_cid' must be of type bytes, got {type(dest_cid).__name__}")

        offset = 1 + len(dest_cid)
        # TODO: maybe the length of a 1-RTT packet can be deduced from the decryption/removing protection later?
        #  For now, simply parse QUIC frames until end of data or error
        frames, consumed = parse_all_quic_frames(data[offset + packet_number_length:])
        return ShortHeaderPacket(destination_cid=dest_cid,
                                 spin_bit=spin_bit, key_phase=key_phase,
                                 packet_number=int.from_bytes(data[offset:offset + packet_number_length]),
                                 payload=frames), offset + packet_number_length + consumed

def create_quic_packet(packet_type: QuicPacketType, destination_cid: bytes, **kwargs) -> QuicPacket:
    assert packet_type is not None
    assert destination_cid is not None

    if packet_type == QuicPacketType.ONE_RTT:
        required_keys = {"packet_number", "payload"}
        if not required_keys.issubset(kwargs):
            raise ValueError(f"Missing required keyword arguments for {packet_type}: {required_keys - kwargs.keys()}")
        return ShortHeaderPacket(destination_cid=destination_cid, **kwargs)
    assert packet_type == QuicPacketType.INITIAL
    if "source_cid" not in kwargs:
        raise ValueError(f"Missing required keyword argument 'source_cid' for {packet_type}")
    return LongHeaderPacket(destination_cid=destination_cid, **kwargs)

def decode_quic_packet(byte_stream: bytes, destination_cid: bytes = None) -> tuple[Optional[QuicPacket], int]:
    if not len(byte_stream):
        return None, 0
    try:
        if (byte_stream[0] & 0b10000000) != 0:  # Long header
            return LongHeaderPacket.decode_all_bytes(byte_stream)
        else:  # Short header
            return ShortHeaderPacket.decode_all_bytes(byte_stream, destination_cid=destination_cid)
    except ValueError:
        # TODO: log?
        return None, 0

def decode_udp_packet(payload: bytes, destination_cid: bytes = None):
    """
    Generator that yields each QUIC packet contained in a UDP datagram.
    :param payload: bytes to be decoded into 1 or multiple QUIC packets
    :param destination_cid: optional destination connection ID, which is required for decoding 1-RTT QUIC packets
    """
    offset = 0
    while offset < len(payload):
        # Skip NUL padding bytes (PADDING frames)
        if payload[offset] == 0x00:
            offset += 1
            continue

        # Try to decode one packet from current position
        packet, consumed = decode_quic_packet(payload[offset:], destination_cid=destination_cid)
        if consumed <= 0 or packet is None:
            break  # stop parsing

        yield packet
        offset += consumed


def encode_packet_number(full_pn: int, largest_acked: int = None) -> bytes:
    """
    Select an appropriate size for packet number encodings.

    full_pn is the full packet number of the packet being sent.
    largest_acked is the largest packet number that has been acknowledged by the peer in the current packet number
      space, if any.

    See: Appendix A - Sample Packet Number Encoding Algorithm
    """

    # The number of bits must be at least one more than the base-2 logarithm of the number of contiguous unacknowledged
    # packet numbers, including the new packet.
    if largest_acked is None:
        num_unacked = full_pn + 1
    else:
        num_unacked = full_pn - largest_acked

    min_bits = math.log(num_unacked, 2) + 1
    num_bytes = math.ceil(min_bits / 8)

    # Encode the integer value and truncate to the num_bytes least significant bytes.
    total_bytes = (full_pn.bit_length() + 7) // 8 or 1  # Min 1 byte
    encoded_bytes = full_pn.to_bytes(total_bytes, byteorder="big", signed=False)
    # Truncate to the least significant num_bytes
    return encoded_bytes[-num_bytes:]


def decode_packet_number(truncated_pn: int, pn_nbits: int, largest_pn: int) -> int:
    """
    Recover a packet number from a truncated packet number.

    truncated_pn is the value of the Packet Number field.
    pn_nbits is the number of bits in the Packet Number field (8, 16, 24, or 32).
    largest_pn is the largest packet number that has been successfully processed in the current packet number space.

    See: Appendix A - Sample Packet Number Decoding Algorithm
    """
    expected_pn = largest_pn + 1
    pn_win = 1 << pn_nbits
    pn_hwin = pn_win / 2
    pn_mask = pn_win - 1

    # The incoming packet number should be greater than
    # expected_pn - pn_hwin and less than or equal to
    # expected_pn + pn_hwin
    #
    # This means we cannot just strip the trailing bits from
    # expected_pn and add the truncated_pn because that might
    # yield a value outside the window.
    #
    # The following code calculates a candidate value and
    # makes sure it's within the packet number window.
    # Note the extra checks to prevent overflow and underflow.
    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
    if candidate_pn <= expected_pn - pn_hwin and candidate_pn < (1 << 62) - pn_win:
        return candidate_pn + pn_win
    elif candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
        return candidate_pn - pn_win
    else:
        return candidate_pn
