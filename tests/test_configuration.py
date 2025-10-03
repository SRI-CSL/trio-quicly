#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
import textwrap

import quicly.configuration as cfg  # or `import configuration as cfg`
from quicly.frame import (
    TransportParameter,
    encode_transport_params,
    decode_transport_params,
    ConfigFrame,
)

DEFAULTS_TP = """\
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
"""


def _write_transport_defaults(tmp_path, body=DEFAULTS_TP):
    p = tmp_path / "transport_defaults.toml"
    p.write_text(body, encoding="utf-8")
    return p


def _clear_tp_defaults_cache_if_any():
    # If your module caches TOML defaults, clear between tests
    if hasattr(cfg, "_tp_defaults_from_toml"):
        try:
            cfg._tp_defaults_from_toml.cache_clear()  # type: ignore[attr-defined]
        except Exception:
            pass


def test_load_defaults_only(monkeypatch, tmp_path):
    """
    With only the version-controlled transport_defaults.toml present,
    QuicConfiguration.load should:
      - use Python defaults for top-level fields (logging_level, ipv6)
      - construct transport_local from the TOML defaults
      - keep transport_peer as None
    """
    monkeypatch.chdir(tmp_path)
    _write_transport_defaults(tmp_path)
    _clear_tp_defaults_cache_if_any()

    conf = cfg.QuicConfiguration.load()

    # Top-level defaults (from Python)
    assert conf.logging_level == "INFO"
    assert conf.ipv6 is False

    # Transport defaults (from TOML)
    tp = conf.transport_local
    assert tp.max_udp_payload_size == 65527
    assert tp.initial_max_data == 0
    assert tp.ack_delay_exponent == 3
    assert tp.initial_padding_target == 1200

    # Peer is not set at load time
    assert conf.transport_peer is None


def test_load_with_toml_file_top_and_transport(monkeypatch, tmp_path):
    """
    Provide a separate config TOML with top-level keys and a [transport] section.
    Unknown keys must be ignored. Valid ones override defaults.
    ENV not set here; TOML should be applied.
    """
    monkeypatch.chdir(tmp_path)
    _write_transport_defaults(tmp_path)
    _clear_tp_defaults_cache_if_any()

    config_toml = tmp_path / "quicly_config.toml"
    config_toml.write_text(textwrap.dedent("""
        # top-level overrides
        logging_level = "DEBUG"
        ipv6 = true
        unknown_top = 123  # should be ignored

        [transport]
        initial_max_data = 65536
        max_ack_delay = 20
        unknown_tp = "ignored"
    """).strip(), encoding="utf-8")

    conf = cfg.QuicConfiguration.load(toml_path=str(config_toml))

    # Top-level overrides applied
    assert conf.logging_level == "DEBUG"
    assert conf.ipv6 is True

    # Transport overrides applied from [transport]
    tp = conf.transport_local
    assert tp.initial_max_data == 65536
    assert tp.max_ack_delay == 20

    # Unspecified transport keys remain at defaults
    assert tp.max_udp_payload_size == 65527
    assert tp.disable_active_migration is False

    # Peer remains None
    assert conf.transport_peer is None


def test_env_overrides_applied(monkeypatch, tmp_path):
    """
    ENV overrides:
      - Top-level via QUICKLY__*
      - Transport via QUICLY_TP__*
    They should apply on top of defaults (no TOML file here).
    """
    monkeypatch.chdir(tmp_path)
    _write_transport_defaults(tmp_path)
    _clear_tp_defaults_cache_if_any()

    # Top-level ENV
    monkeypatch.setenv("QUICKLY__LOGGING_LEVEL", "WARNING")
    monkeypatch.setenv("QUICKLY__IPV6", "true")

    # Transport ENV
    monkeypatch.setenv("QUICLY_TP__INITIAL_MAX_DATA", "99999")
    monkeypatch.setenv("QUICLY_TP__DISABLE_ACTIVE_MIGRATION", "true")

    conf = cfg.QuicConfiguration.load()
    assert conf.logging_level == "WARNING"
    assert conf.ipv6 is True

    tp = conf.transport_local
    assert tp.initial_max_data == 99999
    assert tp.disable_active_migration is True
    # Still from defaults:
    assert tp.max_ack_delay == 25


def test_precedence_toml_then_env_then_runtime(monkeypatch, tmp_path):
    """
    Order of application:
      defaults -> TOML -> ENV -> runtime_overrides
    Later sources override earlier ones.
    """
    monkeypatch.chdir(tmp_path)
    _write_transport_defaults(tmp_path)
    _clear_tp_defaults_cache_if_any()

    # TOML file sets DEBUG + transport values
    config_toml = tmp_path / "quicly_config.toml"
    config_toml.write_text(textwrap.dedent("""
        logging_level = "DEBUG"
        ipv6 = true

        [transport]
        initial_max_data = 111
        ack_delay_exponent = 5
    """).strip(), encoding="utf-8")

    # ENV tweaks some of them
    monkeypatch.setenv("QUICKLY__LOGGING_LEVEL", "ERROR")             # overrides DEBUG
    monkeypatch.setenv("QUICLY_TP__ACK_DELAY_EXPONENT", "7")          # overrides TOML 5

    # runtime overrides have the final say
    runtime = {
        "logging_level": "CRITICAL",                                  # overrides ENV ERROR
        "transport": {
            "initial_max_data": 222,                                  # overrides TOML 111
            "max_datagram_frame_size": 1200,                          # added here
        },
        "unknown_top": "ignored",                                     # ignored safely
    }

    conf = cfg.QuicConfiguration.load(
        toml_path=str(config_toml),
        runtime_overrides=runtime,
    )

    # Final top-level
    assert conf.logging_level == "CRITICAL"
    # ipv6 came from TOML (not overridden elsewhere)
    assert conf.ipv6 is True

    # Final transport
    tp = conf.transport_local
    assert tp.initial_max_data == 222               # runtime > TOML
    assert tp.ack_delay_exponent == 7               # ENV > TOML
    assert tp.max_datagram_frame_size == 1200       # runtime
    # Unchanged from defaults:
    assert tp.max_ack_delay == 25

    # Peer untouched
    assert conf.transport_peer is None

def test_datagram_configuration():
    config = cfg.QuicConfiguration()
    assert config.transport_local.max_datagram_frame_size == 0
    transport_parameters = {"max_datagram_frame_size": 1200}  # add DATAGRAM support
    changed = config.update_transport(transport_parameters, target="local")
    assert changed is True
    assert config.transport_local.max_datagram_frame_size == 1200
    # until peer is set, effectively no DATAGRAM support?
    assert config.effective_max_datagram == 0
