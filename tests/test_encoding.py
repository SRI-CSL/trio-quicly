import pytest

from trioquic.crypto import decode_var_length_int, encode_packet_number, decode_packet_number
from trioquic.packet import LongHeaderPacket, create_quic_packet, QuicPacketType


# For example, the eight-byte sequence 0xc2197c5eff14e88c decodes to the decimal value 151,288,809,941,952,652;
# the four-byte sequence 0x9d7f3e7d decodes to 494,878,333;
# the two-byte sequence 0x7bbd decodes to 15,293;
# and the single byte 0x25 decodes to 37 (as does the two-byte sequence 0x4025).
def test_var_int_encoding():
    assert decode_var_length_int(bytes.fromhex("c2197c5eff14e88c")) == (int("151,288,809,941,952,652".replace(",", "")), 8)
    assert decode_var_length_int(bytes.fromhex("9d7f3e7d")) == (int("494,878,333".replace(",", "")), 4)
    assert decode_var_length_int(bytes.fromhex("7bbd")) == (int("15,293".replace(",", "")), 2)
    assert decode_var_length_int(bytes.fromhex("25")) == (37, 1)
    assert decode_var_length_int(bytes.fromhex("4025")) == (37, 2)

# For example, if an endpoint has received an acknowledgment for packet 0xabe8b3 and is sending a packet with a number
# of 0xac5c02, there are 29,519 (0x734f) outstanding packet numbers. In order to represent at least twice this range
# (59,038 packets, or 0xe69e), 16 bits are required. In the same state, sending a packet with a number of 0xace8fe uses
# the 24-bit encoding, because at least 18 bits are required to represent twice the range (131,222 packets, or 0x020096).
def test_pkt_number_encoding():
    encoded_pn = encode_packet_number(0xac5c02, 0xabe8b3)
    assert len(encoded_pn) == 2  # 16 bits required => 2 bytes or 16-bit encoding
    encoded_pn = encode_packet_number(0xace8fe, 0xabe8b3)
    assert len(encoded_pn) == 3  # 18 bits required => 3 bytes or 24-bit encoding
    encoded_pn = encode_packet_number(0xac5c02)
    assert len(encoded_pn) == 3

# For example, if the highest successfully authenticated packet had a packet number of 0xa82f30ea, then a packet
# containing a 16-bit value of 0x9b32 will be decoded as 0xa82f9b32.
def test_pkt_number_decoding():
    assert decode_packet_number(0x9b32, 16, 0xa82f30ea) == 0xa82f9b32

def test_quick_packets():
    sample_dcid = bytes.fromhex("c2 19 7c 5e ff 14 e8")  # 7 Bytes long
    packet_number = 0xac5c02
    encoded_pn = encode_packet_number(packet_number)
    assert packet_number.bit_length() / 8 == len(encoded_pn)

    one_rtt_pkt = create_quic_packet(QuicPacketType.ONE_RTT, sample_dcid,
                                     spin_bit = False, key_phase = True,
                                     packet_number = packet_number, payload = 0xFF)
    first_byte = one_rtt_pkt.encode_first_byte()
    print("\n{:08b}".format(first_byte))
    # TODO: assert that first bit == 0, second bit == 1, 3rd bit == spin_bit (0), 6th bit == key_phase (1),
    #   7..8 bits encode 3 == len(encoded_pn)

    ver_neg_pkt = create_quic_packet(QuicPacketType.VERSION_NEGOTIATION, sample_dcid)
    first_byte = ver_neg_pkt.encode_first_byte()
    print("{:08b}".format(first_byte))
    # TODO: assert that first bit == 1
