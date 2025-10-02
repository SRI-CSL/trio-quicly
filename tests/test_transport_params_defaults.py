import pytest

import quicly.configuration as cfg
from quicly.frame import (
    TransportParameter,
    encode_transport_params,
    decode_transport_params,
    ConfigFrame,
)

def _decode_map(tlv: bytes):
    out = {}
    for tp in decode_transport_params(tlv):
        out[tp.param_id] = tp.value
    return out

def _is_flag_default(pid, val):
    return isinstance(val, bool)

def test_include_defaults_emits_expected_set():
    defaults = cfg.load_transport_parameters().to_id_value_map()
    tlv = encode_transport_params([], include_defaults=True)
    decoded = _decode_map(tlv)

    # All integer defaults must be present; false flags must omit length; true flags must be present with zero-length
    for pid, default_value in defaults.items():
        if _is_flag_default(pid, default_value):
            assert pid in decoded, f"flag {pid} missing"
            if default_value:
                assert decoded[pid] is True
            else:
                assert decoded[pid] is False
        else:
            assert pid in decoded, f"int param {pid} missing"
            assert decoded[pid] == default_value, f"int param {pid} value mismatch"

def test_include_defaults_with_override_last_wins():
    defaults = cfg.load_transport_parameters().to_id_value_map()
    int_pids = [id for id, val in defaults.items() if isinstance(val, int)]
    if not int_pids:
        pytest.skip("no integer defaults defined")
    pid = int_pids[0]
    override = defaults[pid] + 123

    tlv = encode_transport_params([TransportParameter(pid, override)], include_defaults=True)
    decoded = _decode_map(tlv)

    for p, dv in defaults.items():
        assert p in decoded
        if isinstance(dv, bool):
            if dv:
                assert decoded[p] is True
            else:
                assert decoded[p] is False
        else:
            if p == pid:
                assert decoded[p] == override
            else:
                assert decoded[p] == dv

def test_configframe_with_include_defaults_roundtrip():
    defaults = cfg.load_transport_parameters().to_id_value_map()
    tlv = encode_transport_params([], include_defaults=True)
    cf = ConfigFrame(decode_transport_params(tlv))
    body = cf.encode()
    parsed, used = ConfigFrame.decode(body)
    assert used == len(body)

    by_id = {tp.param_id: tp.value for tp in parsed.transport_parameters}
    for pid, dv in defaults.items():
        assert pid in by_id
        if _is_flag_default(pid, dv):
            if dv:
                assert by_id[pid] is True
            else:
                assert by_id[pid] is False
        else:
            assert by_id[pid] == dv

def test_as_list():
    tp = cfg.load_transport_parameters(defaults_path="transport_defaults.toml",
                                   runtime_overrides={"initial_max_data": 65536})

    wire_all = tp.as_list(exclude_defaults=False)  # full set
    assert len(wire_all) == len(cfg.TP_REGISTRY)

    wire_min = tp.as_list(exclude_defaults=True)  # only diffs vs TOML defaults
    assert len(wire_min) == 1

    tp = cfg.load_transport_parameters()
    tp.max_udp_payload_size = 24000
    no_defaults = tp.as_list(exclude_defaults=True)
    assert len(no_defaults) == 1

    assert tp.initial_padding_target == 1200  # default value
    tp.update({"initial_padding_target": 2400})
    assert tp.initial_padding_target == 2400

DEFAULTS = """\
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
"""

def test_config_from_files_and_env(tmp_path, monkeypatch):
    # 1) create on-the-fly files
    defaults_path = tmp_path / "transport_defaults.toml"
    defaults_path.write_text(DEFAULTS, encoding="utf-8")

    override_path = tmp_path / "tp_test.toml"
    override_path.write_text(
        # flat or [transport]-scoped; both are supported by the loader
        "initial_max_data = 65536\nmax_ack_delay_ms = 20\n",
        encoding="utf-8",
    )

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        #
        "initial_max_data = 65536\nmax_ack_delay_ms = 20\n",
        encoding="utf-8",
    )

    # 2) optionally chdir so relative names work (if you don’t pass paths explicitly)
    monkeypatch.chdir(tmp_path)

    # 3) ENV overrides
    monkeypatch.setenv("QUICLY_TP__DISABLE_ACTIVE_MIGRATION", "true")
    monkeypatch.setenv("QUICLY_TP__MAX_DATAGRAM_FRAME_SIZE", "1200")

    # (if you memoize defaults inside the module, clear the cache per test run)
    if hasattr(cfg, "_tp_defaults_from_toml"):
        try:
            cfg._tp_defaults_from_toml.cache_clear()  # lru_cache safety
        except Exception:
            pass

    # 4) load using explicit paths (recommended; avoids surprises)
    tp = cfg.load_transport_parameters(
        defaults_path=str(defaults_path),
        override_path=str(override_path),  # optional
        # env_prefix defaults to "QUICLY_TP__"
        runtime_overrides={"ack_delay_exponent": 10},  # optional
    )

    # 5) assert effective values
    assert tp.initial_max_data == 65536            # from override file
    assert tp.max_ack_delay_ms == 20               # from override file
    assert tp.disable_active_migration is True     # from ENV
    assert tp.max_datagram_frame_size == 1200      # from ENV
    assert tp.ack_delay_exponent == 10             # from runtime overrides
    assert tp.max_udp_payload_size == 65527        # from defaults
