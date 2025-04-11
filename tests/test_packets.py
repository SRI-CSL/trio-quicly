import math
import secrets

from trioquic.crypto import decode_var_length_int, encode_packet_number, decode_packet_number
from trioquic.packet import create_quic_packet, QuicPacketType, QuicProtocolVersion, \
    VersionNegotiationPacket, ShortHeaderPacket, decode_quic_packet, \
    LongHeaderPacket, decode_udp_packet
from trioquic.frame import encode_var_length_int, QuicFrame, QuicFrameType, MaxDataFrame, parse_all_quic_frames

sample_dcid = bytes.fromhex("c2 19 7c 5e ff 14 e8")  # 7 Bytes long
sample_scid = bytes.fromhex("ff 14 e8 8c")  # 4 Bytes long
packet_number = 0xac5c02
encoded_pn = encode_packet_number(packet_number)


# For example, the eight-byte sequence 0xc2197c5eff14e88c decodes to the decimal value 151,288,809,941,952,652;
# the four-byte sequence 0x9d7f3e7d decodes to 494,878,333;
# the two-byte sequence 0x7bbd decodes to 15,293;
# and the single byte 0x25 decodes to 37 (as does the two-byte sequence 0x4025).

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

def check_long_header(packet: bytes, expected_length: int, expected_dcid: bytes, expected_scid: bytes):
    assert len(packet) == expected_length
    assert QuicProtocolVersion.VERSION_1 == int.from_bytes(packet[1:5])
    assert expected_dcid == packet[6:13]
    assert expected_scid == packet[14:18]

def test_ver_neg_pkt():
    silly_version = int.from_bytes(bytes.fromhex("aa bb cc dd"))
    ver_neg_pkt = create_quic_packet(QuicPacketType.VERSION_NEGOTIATION, sample_dcid,
                                     source_cid=sample_scid,
                                     supported_versions=[QuicProtocolVersion.VERSION_1,
                                                         silly_version])
    first_byte = ver_neg_pkt.encode_first_byte()
    assert "10000000" == f"{first_byte:08b}"  # first bit == 1
    packet = ver_neg_pkt.encode_all_bytes()
    # print(f"\n{packet.hex(' ')}")
    assert len(packet) == 26
    assert QuicProtocolVersion.NEGOTIATION == int.from_bytes(packet[1:5])
    assert sample_dcid == packet[6:13]
    assert sample_scid == packet[14:18]
    assert QuicProtocolVersion.VERSION_1 == int.from_bytes(packet[18:22])

    decoded_pkt, consumed = VersionNegotiationPacket.decode_all_bytes(packet)
    assert len(decoded_pkt.supported_versions) == 2
    assert QuicProtocolVersion.VERSION_1 == decoded_pkt.supported_versions[0]
    assert silly_version == decoded_pkt.supported_versions[1]

    # adding 2 extra bytes at end that should be safely ignored:
    decoded_pkt, consumed = decode_quic_packet(
        bytes.fromhex("80 00 00 00 00 07 c2 19 7c 5e ff 14 e8 04 ff 14 e8 8c 00 00 00 01 aa bb cc dd ff ee"))
    assert isinstance(decoded_pkt, VersionNegotiationPacket)
    assert len(decoded_pkt.supported_versions) == 2

def test_short_header():
    frames = [QuicFrame(frame_type=QuicFrameType.MAX_DATA, content=MaxDataFrame(max_data=42)),
              QuicFrame(frame_type=QuicFrameType.PADDING)]
    one_rtt_pkt = create_quic_packet(QuicPacketType.ONE_RTT, sample_dcid,
                                     spin_bit=False, key_phase=True,
                                     packet_number=packet_number, payload=frames)
    first_byte = one_rtt_pkt.encode_first_byte()
    assert "01000110" == f"{first_byte:08b}"  # first bit == 0, second bit == 1, 3rd bit == spin_bit (0),
                                              # 6th bit == key_phase (1), 7..8 bits encode 2 == len(encoded_pn) - 1
    packet = one_rtt_pkt.encode_all_bytes()
    # print(f"\n{packet.hex(' ')}")
    assert len(packet) == 14
    assert sample_dcid == packet[1:8]  # 2..8 bytes are destination connection ID
    assert packet_number == int.from_bytes(packet[8:8+len(encoded_pn)])  # 9..11 bytes are packet number

    decoded_pkt, consumed = ShortHeaderPacket.decode_all_bytes(packet + b'garbage', destination_cid=sample_dcid)
    assert decoded_pkt.destination_cid == sample_dcid
    assert decoded_pkt.packet_number == packet_number
    assert consumed == 14
    assert len(decoded_pkt.payload) == 2

    decoded_pkt, consumed = decode_quic_packet(bytes.fromhex("46 c2 19 7c 5e ff 14 e8 ac 5c 02 ") +
                                               b''.join([frame.encode() for frame in frames]) +
                                               b'\x1egarbage',  # HANDSHAKE DONE frame
                                               destination_cid=sample_dcid)
    assert isinstance(decoded_pkt, ShortHeaderPacket)
    assert consumed == 15
    assert len(decoded_pkt.payload) == 3

def test_initial_packets():
    assert max(math.ceil(packet_number.bit_length() / 8), 1) == len(encoded_pn)

    frames, _ = parse_all_quic_frames(bytes.fromhex("01 00 00 00"))
    initial_pkt = create_quic_packet(QuicPacketType.INITIAL, sample_dcid, source_cid=sample_scid,
                                     packet_number=packet_number, payload=frames)
    first_byte = initial_pkt.encode_first_byte()
    assert "11000010" == f"{first_byte:08b}"  # bits 3..4 = INITIAL,  bits 5..6 = 0 (reserved), bits 7..8 encode 2 == len(encoded_pn) - 1
    packet = initial_pkt.encode_all_bytes()
    # print(f"\n{packet.hex(' ')}")
    check_long_header(packet, 27, sample_dcid, sample_scid)
    (length, start) = decode_var_length_int(packet[19:])
    assert (length, start) == (len(encoded_pn) + 4, 1)  # payload is 4 bytes long
    assert packet_number == int.from_bytes(packet[19+start:19+start+len(encoded_pn)])

    tkn = bytes.fromhex("c5 00 7f ff 25")
    initial_pkt_w_tkn = create_quic_packet(QuicPacketType.INITIAL, sample_dcid, source_cid=sample_scid,
                                           token=tkn, packet_number=packet_number,
                                           payload=[QuicFrame(frame_type=QuicFrameType.MAX_DATA, content=MaxDataFrame(max_data=42))])
    first_byte = initial_pkt_w_tkn.encode_first_byte()
    assert "11000010" == f"{first_byte:08b}"  # bits 3..4 = INITIAL,  bits 5..6 = 0 (reserved), bits 7..8 encode 2 == len(encoded_pn) - 1
    packet = initial_pkt_w_tkn.encode_all_bytes()
    # print(f"\n{packet.hex(' ')}")
    check_long_header(packet, 30, sample_dcid, sample_scid)
    encoded_tkn_len = encode_var_length_int(len(tkn))
    (tkn_len, offset) = decode_var_length_int(packet[18:])
    assert (tkn_len, offset) == (int.from_bytes(encoded_tkn_len), 1)  # value of 5 fits into 1 byte
    assert tkn == packet[18+offset:18+offset+tkn_len]
    (length, start) = decode_var_length_int(packet[18+offset+tkn_len:])
    assert (length, start) == (len(encoded_pn) + 2, 1)  # payload is 2 bytes long
    assert packet_number == int.from_bytes(packet[24+start:24+start+len(encoded_pn)])

    # adding some padding of NUL bytes at the end
    decoded_pkt, consumed = decode_quic_packet(
        bytes.fromhex("c2 00 00 00 01 07 c2 19 7c 5e ff 14 e8 04 ff 14 e8 8c 05 c5 00 7f ff 25 07 ac 5c 02 01 00 00 00 00 00"))
    assert isinstance(decoded_pkt, LongHeaderPacket)
    assert decoded_pkt.is_long_header
    assert decoded_pkt.packet_type == QuicPacketType.INITIAL
    assert decoded_pkt.destination_cid == sample_dcid
    assert decoded_pkt.source_cid == sample_scid
    assert decoded_pkt.token == tkn
    assert decoded_pkt.packet_number == packet_number
    assert decoded_pkt.packet_number_length == len(encoded_pn)
    assert len(decoded_pkt.payload) == 4

def test_quic_packets():
    frames, _ = parse_all_quic_frames(bytes.fromhex("00 1e"))

    zero_rtt_pkt = create_quic_packet(QuicPacketType.ZERO_RTT, sample_dcid, source_cid=sample_scid,
                                      packet_number=packet_number, payload=frames)
    first_byte = zero_rtt_pkt.encode_first_byte()
    assert "11010010" == f"{first_byte:08b}"  # bits 3..4 = 0-RTT,  bits 5..6 = 0 (reserved), bits 7..8 encode 2 == len(encoded_pn) - 1
    packet = zero_rtt_pkt.encode_all_bytes()
    # print(f"\n{packet.hex(' ')}")
    check_long_header(packet, 24, sample_dcid, sample_scid)
    (length, start) = decode_var_length_int(packet[18:])
    assert (length, start) == (len(encoded_pn) + 2, 1)  # payload is 2 bytes long
    assert packet_number == int.from_bytes(packet[18+start:18+start+len(encoded_pn)])

    handshake_pkt = create_quic_packet(QuicPacketType.HANDSHAKE, sample_dcid, source_cid=sample_scid,
                                       packet_number=packet_number, payload=frames)
    first_byte = handshake_pkt.encode_first_byte()
    assert "11100010" == f"{first_byte:08b}"  # bits 3-4 = HANDSHAKE,  bits 5-6 = 0 (reserved), bits 7-8 encode 2 == len(encoded_pn) - 1
    packet = handshake_pkt.encode_all_bytes()
    # print(f"\n{packet.hex(' ')}")
    check_long_header(packet, 24, sample_dcid, sample_scid)
    (length, start) = decode_var_length_int(packet[18:])
    assert (length, start) == (len(encoded_pn) + 2, 1)  # payload is 2 bytes long
    assert packet_number == int.from_bytes(packet[18+start:18+start+len(encoded_pn)])

    decoded_pkt, consumed = decode_quic_packet(packet)
    assert isinstance(decoded_pkt, LongHeaderPacket)
    assert decoded_pkt.packet_type == QuicPacketType.HANDSHAKE
    assert decoded_pkt.version == QuicProtocolVersion.VERSION_1
    assert decoded_pkt.destination_cid == sample_dcid
    assert decoded_pkt.source_cid == sample_scid
    assert decoded_pkt.packet_number == packet_number
    assert decoded_pkt.packet_number_length == len(encoded_pn)
    assert len(decoded_pkt.payload) == 2

def test_retry_packets():

    tkn = bytes.fromhex("c5 00 7f ff 25")
    integrity_tag = secrets.token_bytes(16)
    retry_pkt = create_quic_packet(QuicPacketType.RETRY, sample_dcid, source_cid=sample_scid,
                                   token=tkn,
                                   integrity_tag=integrity_tag)
    first_byte = retry_pkt.encode_first_byte()
    assert "11110000" == f"{first_byte:08b}"  # bits 3-4 = RETRY, bits 5-8 unused
    packet = retry_pkt.encode_all_bytes()
    # print(f"\npacket = {packet.hex(' ')}")
    check_long_header(packet, 18+len(tkn)+16, sample_dcid, sample_scid)
    assert tkn == packet[18:18+len(tkn)]
    assert integrity_tag == packet[-16:]

    decoded_pkt, consumed = decode_quic_packet(packet)
    assert isinstance(decoded_pkt, LongHeaderPacket)
    assert decoded_pkt.packet_type == QuicPacketType.RETRY
    assert decoded_pkt.version == QuicProtocolVersion.VERSION_1
    assert decoded_pkt.destination_cid == sample_dcid
    assert decoded_pkt.source_cid == sample_scid
    assert decoded_pkt.token == tkn
    assert decoded_pkt.integrity_tag == integrity_tag

def test_udp_packets():
    tkn = bytes.fromhex("c5 00 7f ff 25")
    frames, _ = parse_all_quic_frames(bytes.fromhex("01 1e"))
    initial_pkt_w_tkn = create_quic_packet(QuicPacketType.INITIAL, sample_dcid, source_cid=sample_scid,
                                           token=tkn, packet_number=packet_number, payload=frames)
    initial_encoded = initial_pkt_w_tkn.encode_all_bytes()
    handshake_pkt = create_quic_packet(QuicPacketType.HANDSHAKE, sample_dcid, source_cid=sample_scid,
                                       packet_number=packet_number, payload=frames)
    handshake_encoded = handshake_pkt.encode_all_bytes()

    packets = list(decode_udp_packet(bytes(0)))
    assert len(packets) == 0
    packets = list(decode_udp_packet(handshake_encoded))
    assert len(packets) == 1
    # ignore NUL padding:
    packets = list(decode_udp_packet(initial_encoded + handshake_encoded + bytes.fromhex("00 00 00 00 00")))
    assert len(packets) == 2
    packets = list(decode_udp_packet(initial_encoded + bytes.fromhex("00 00 00") + handshake_encoded))
    assert len(packets) == 2
