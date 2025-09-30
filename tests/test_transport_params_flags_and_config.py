import textwrap

try:
    import quicly.configuration as cfg
except Exception:  # pragma: no cover
    import configuration as cfg


DEFAULTS_TOML = textwrap.dedent("""
max_idle_timeout_ms = 0
max_udp_payload_size = 65527
initial_max_data = 0
initial_max_stream_data_bidi_local = 0
initial_max_stream_data_bidi_remote = 0
initial_max_stream_data_uni = 0
initial_max_streams_bidi = 0
initial_max_streams_uni = 0
ack_delay_exponent = 3
max_ack_delay_ms = 25
disable_active_migration = false
active_connection_id_limit = 2
max_datagram_frame_size = 0
initial_padding_target = 1200
""").lstrip()


def _write_defaults(tmp_path, body=DEFAULTS_TOML):
    p = tmp_path / "transport_defaults.toml"
    p.write_text(body, encoding="utf-8")
    return p


def test_tp_to_id_value_map_and_flag_presence(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    tp = cfg.load_transport_parameters(
        runtime_overrides={"disable_active_migration": True, "initial_max_data": 111}
    )
    idmap = tp.to_id_value_map()

    # integers present with numeric values
    assert idmap[0x04] == 111
    assert idmap[0x01] == 0
    # flag present iff True
    assert idmap.get(0x0c) is True

    # turning the flag off removes it from the map
    tp2 = cfg.load_transport_parameters(
        runtime_overrides={"disable_active_migration": False}
    )
    idmap2 = tp2.to_id_value_map()
    assert 0x0c not in idmap2


def test_as_list_flag_encoding_rules(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    tp = cfg.load_transport_parameters(runtime_overrides={"disable_active_migration": True})
    out = tp.as_list(exclude_defaults=False)
    d = dict(out)

    # presence => True for flags; no False encoding
    assert d[0x0c] is True
    # try a typical numeric:
    assert isinstance(d[0x01], int)
