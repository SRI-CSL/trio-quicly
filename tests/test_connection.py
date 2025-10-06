#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

import pytest

from quicly.configuration import QuicConfiguration
from quicly.connection import SimpleQuicConnection, get_cid_from_header
from quicly.frame import parse_all_quic_frames, QuicFrame, QuicFrameType, MaxDataFrame
from quicly.packet import create_quic_packet, QuicPacketType

sample_dcid = bytes.fromhex("c2 19 7c 5e ff 14 e8")  # 7 Bytes long
sample_scid = bytes.fromhex("ff 14 e8 8c")  # 4 Bytes long
packet_number = 0xac5c02

# def test_wrong_client_conf1():
#     with pytest.raises(AssertionError):
#         SimpleQuicConnection(
#             configuration=QuicConfiguration(is_client=True),
#             original_destination_connection_id=b'bad')
#
# def test_wrong_client_conf2():
#     with pytest.raises(AssertionError):
#         SimpleQuicConnection(
#             configuration=QuicConfiguration(is_client=True),
#             retry_source_connection_id=b'bad')
#
# def test_wrong_server_conf():
#     with pytest.raises(AssertionError):
#         SimpleQuicConnection(
#             configuration=QuicConfiguration(is_client=False)
#         )

def test_no_endpoint():
    with pytest.raises(AssertionError):
        SimpleQuicConnection(None, ("bla", 12345), 0, 0,
                             QuicConfiguration())

def test_get_dcid_from_packet():
    frames, _ = parse_all_quic_frames(bytes.fromhex("01 00 00 00"))

    initial_pkt = create_quic_packet(QuicPacketType.INITIAL, sample_dcid, source_cid=sample_scid,
                                     packet_number=packet_number, payload=frames)
    dcid = get_cid_from_header(initial_pkt.encode_all_bytes(), len(sample_scid))
    assert dcid == sample_scid

    initial_pkt = create_quic_packet(QuicPacketType.INITIAL, b'', source_cid=sample_dcid,
                                     packet_number=packet_number, payload=frames)
    dcid = get_cid_from_header(initial_pkt.encode_all_bytes(), len(sample_dcid))
    assert dcid == sample_dcid

    dcid = get_cid_from_header(bytes.fromhex("11 00 11 10 00 00 00 ff ef b0"), 3)
    assert dcid == None

    frames = [QuicFrame(frame_type=QuicFrameType.MAX_DATA, content=MaxDataFrame(max_data=42)),
              QuicFrame(frame_type=QuicFrameType.PADDING)]
    one_rtt_pkt = create_quic_packet(QuicPacketType.ONE_RTT, sample_dcid,
                                     spin_bit=False, key_phase=True,
                                     packet_number=packet_number, payload=frames)
    dcid = get_cid_from_header(one_rtt_pkt.encode_all_bytes(), len(sample_dcid))
    assert dcid == sample_dcid

    dcid = get_cid_from_header(bytes.fromhex("01 00 00 00 ff ef b0"), 3)
    assert dcid == None