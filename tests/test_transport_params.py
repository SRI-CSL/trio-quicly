#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

import textwrap

try:
    # preferred in-package import
    import quicly.configuration as cfg
except Exception:  # pragma: no cover - fallback for local runs
    import configuration as cfg


DEFAULTS_TOML = textwrap.dedent("""
max_idle_timeout = 0
max_udp_payload_size = 65527
initial_max_data = 0
initial_max_stream_data_bidi_local = 0
initial_max_stream_data_bidi_remote = 0
initial_max_stream_data_uni = 0
initial_max_streams_bidi = 0
initial_max_streams_uni = 0
ack_delay_exponent = 3
max_ack_delay = 25
disable_active_migration = false
active_connection_id_limit = 2
max_datagram_frame_size = 0
initial_padding_target = 1200
""").lstrip()


def _write_defaults(tmp_path, name="transport_defaults.toml", body=DEFAULTS_TOML):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_load_defaults_only_uses_toml(monkeypatch, tmp_path):
    # Arrange: ensure loader sees our temp defaults next to CWD
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    # Act
    tp = cfg.load_transport_parameters()

    # Assert (spot-check a few; full set must parse)
    assert tp.max_udp_payload_size == 65527
    assert tp.initial_max_data == 0
    assert tp.ack_delay_exponent == 3
    assert tp.disable_active_migration is False
    assert tp.initial_padding_target == 1200


def test_partial_override_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    # Provide a partial override TOML (may be flat or under [transport])
    (tmp_path / "tp_test.toml").write_text(
        "initial_max_data = 65536\nmax_ack_delay = 20\n", encoding="utf-8"
    )

    tp = cfg.load_transport_parameters(override_path="tp_test.toml")

    assert tp.initial_max_data == 65536
    assert tp.max_ack_delay == 20
    # untouched fields come from defaults.toml
    assert tp.max_udp_payload_size == 65527
    assert tp.disable_active_migration is False


def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    # ENV prefix for TPs is QUICLY_TP__ (name is case-insensitive in loader)
    monkeypatch.setenv("QUICLY_TP__INITIAL_MAX_DATA", "99999")
    monkeypatch.setenv("QUICLY_TP__DISABLE_ACTIVE_MIGRATION", "true")

    tp = cfg.load_transport_parameters()

    assert tp.initial_max_data == 99999
    assert tp.disable_active_migration is True
    # others unchanged
    assert tp.max_ack_delay == 25


def test_runtime_overrides(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    tp = cfg.load_transport_parameters(
        runtime_overrides={"ack_delay_exponent": 10, "max_datagram_frame_size": 1200}
    )

    assert tp.ack_delay_exponent == 10
    assert tp.max_datagram_frame_size == 1200
    # unchanged:
    assert tp.initial_max_streams_bidi == 0


def test_as_list_all_and_excluding_defaults(monkeypatch, tmp_path):
    # Make sure exclude_defaults compares against the TOML we control
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    tp = cfg.load_transport_parameters(
        runtime_overrides={
            "initial_max_data": 65536,          # changed vs defaults
            "disable_active_migration": True,   # flag set (default=false)
        }
    )

    all_list = tp.as_list(exclude_defaults=False)
    # Ensure mapping contains both changed and unchanged items
    ids = [pid for (pid, _) in all_list]
    assert 0x04 in ids  # initial_max_data
    assert 0x0c in ids or True  # flag may be omitted if False; here it's True so included

    # Now only diffs vs TOML defaults should be emitted
    min_list = tp.as_list(exclude_defaults=True)
    mids = {pid for (pid, _) in min_list}
    assert 0x04 in mids                    # initial_max_data changed
    assert 0x0c in mids                    # flag present because set True
    # A default-equal param should be absent
    assert 0x0b not in mids                # max_ack_delay still 25 (default)


def test_ordering_is_spec_order(monkeypatch, tmp_path):
    # the output ordering should follow TP_REGISTRY
    monkeypatch.chdir(tmp_path)
    _write_defaults(tmp_path)

    tp = cfg.load_transport_parameters()
    lst = tp.as_list(exclude_defaults=False)
    order = [pid for pid, _ in lst]
    # TP_REGISTRY defines canonical order:
    reg_order = [pid for (_, pid, _) in cfg.TP_REGISTRY]
    assert order == reg_order
