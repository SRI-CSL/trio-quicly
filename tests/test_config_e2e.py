#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

import quicly.configuration as cfg
from quicly.frame import QuicFrame, QuicFrameType, ConfigFrame, TransportParameter


# --- constants (from spec/registry) ------------------------------------------
TP_ID_DISABLE_ACTIVE_MIGRATION = 0x0C
TP_ID_MAX_DATAGRAM_FRAME_SIZE  = 0x20


def _encode_quic_frame(config: cfg.QuicConfiguration, frame_type: QuicFrameType) -> bytes:
    pairs = config.transport_local.as_list(exclude_defaults=True)
    assert frame_type in [QuicFrameType.CONFIG, QuicFrameType.CONFIG_ACK]
    qf = QuicFrame(frame_type,
                   content=ConfigFrame([TransportParameter.from_pair(pair) for pair in pairs]))
    return qf.encode()


def test_config_roundtrip_client_server(monkeypatch, tmp_path):
    """
    Client local TP → CONFIG → bytes → Server decodes + sets peer TP →
    Server local TP → CONFIG_ACK → bytes → Client decodes + sets peer TP.

    Also checks that False flags are visible in config but omitted on wire when exclude_defaults=True.
    """
    # Ensure transport defaults are available (from your packaged defaults loader);
    # If your code requires specific cwd for test TOMLs, set it:
    monkeypatch.chdir(tmp_path)

    # --- Client side setup ---
    client = cfg.QuicConfiguration.load(runtime_overrides={"transport":{
        "max_idle_timeout": 60000,
        "max_datagram_frame_size": 1200}})
    # Local view should keep False flags visible:
    assert client.transport_local.disable_active_migration is False
    assert client.transport_local.max_idle_timeout == 60000
    assert client.transport_local.max_datagram_frame_size == 1200

    # Build CONFIG from client's LOCAL params, omitting defaults for compactness
    client_encoded = _encode_quic_frame(client, QuicFrameType.CONFIG)

    # --- Server receives CONFIG and updates its PEER TPs from it ---
    decoded, used = QuicFrame.decode(client_encoded)
    assert used == len(client_encoded)
    assert decoded.frame_type == QuicFrameType.CONFIG

    server = cfg.QuicConfiguration.load()
    assert isinstance(decoded.content, ConfigFrame)
    changed = server.update_peer(decoded.content.tps_as_dict())
    assert changed is True
    assert server.transport_peer is not None
    assert server.transport_peer.max_datagram_frame_size == 1200

    # Server's local still default (no DATAGRAM yet)
    assert server.transport_local.max_datagram_frame_size == 0

    # Server decides to support DATAGRAM=2400 locally and replies in CONFIG_ACK
    server.update_local({"max_idle_timeout": 30000, "max_datagram_frame_size": 2400})
    assert server.transport_local.max_datagram_frame_size == 2400
    assert server.effective_max_idle_timeout == 30000

    server_encoded = _encode_quic_frame(server, QuicFrameType.CONFIG_ACK)

    # --- Client receives CONFIG_ACK and updates its PEER TPs from it ---
    decoded2, used2 = QuicFrame.decode(server_encoded)
    assert used2 == len(server_encoded)
    assert decoded2.frame_type == QuicFrameType.CONFIG_ACK
    assert isinstance(decoded2.content, ConfigFrame)
    assert len(decoded2.content.transport_parameters) == 2  # updated 2 TPs

    changed2 = client.update_peer(decoded2.content.tps_as_dict())
    assert changed2 is True
    assert client.transport_peer is not None
    assert client.transport_peer.max_datagram_frame_size == 2400
    assert client.effective_max_idle_timeout == 30000


def test_false_flags_visible_in_config_omitted_on_wire(monkeypatch, tmp_path):
    """
    Ensure we keep False flags in the configuration view but omit them when emitting CONFIG.
    """
    monkeypatch.chdir(tmp_path)
    c = cfg.QuicConfiguration.load()
    # Visible in config:
    assert c.transport_local.disable_active_migration is False

    c_encoded = _encode_quic_frame(c, QuicFrameType.CONFIG)
    # length of encoded CONFIG Frame:
    # 1 (CONFIG type) + 1 (length = 0, as no change from default values) = 2 bytes
    assert len(c_encoded) == 2

    c.update_local({TP_ID_DISABLE_ACTIVE_MIGRATION: True})
    # Visible in config:
    assert c.transport_local.disable_active_migration is True

    c_encoded = _encode_quic_frame(c, QuicFrameType.CONFIG_ACK)
    # length of encoded CONFIG_ACK Frame:
    # 1 (CONFIG_ACK type) + 1 (length = 1 diff from defaults) + 2 (TLV: flag id, length = 0 for True) = 4 bytes
    assert len(c_encoded) == 4

    # looking at single TP encoding:
    tp = TransportParameter.from_pair((TP_ID_DISABLE_ACTIVE_MIGRATION, False))
    tp_encoded = tp.encode()
    # TLV encoded = flag_id (1) only as False omitted = 1
    assert len(tp_encoded) == 1
    tp_decoded, offset = TransportParameter.decode(tp_encoded)
    assert tp_decoded.param_id == TP_ID_DISABLE_ACTIVE_MIGRATION
    assert tp_decoded.value == False
    assert offset == len(tp_encoded)  # full bytestring decoded

    tp = TransportParameter.from_pair((TP_ID_DISABLE_ACTIVE_MIGRATION, True))
    tp_encoded = tp.encode()
    # TLV encoded = flag_id (1) + length = 0 (1) for True = 2
    assert len(tp_encoded) == 2
    tp_decoded, offset = TransportParameter.decode(tp_encoded)
    assert tp_decoded.param_id == TP_ID_DISABLE_ACTIVE_MIGRATION
    assert tp_decoded.value == True
    assert offset == len(tp_encoded)  # full bytestring decoded


def test_name_and_id_overrides_both_work(monkeypatch, tmp_path):
    """
    `update_transport` should accept both field names and numeric IDs.
    """
    monkeypatch.chdir(tmp_path)

    conf = cfg.QuicConfiguration.load()
    # name form
    assert conf.update_local({"max_datagram_frame_size": 1300}) is True
    assert conf.transport_local.max_datagram_frame_size == 1300

    # id form
    assert conf.update_local({TP_ID_MAX_DATAGRAM_FRAME_SIZE: 1400}) is True
    assert conf.transport_local.max_datagram_frame_size == 1400
