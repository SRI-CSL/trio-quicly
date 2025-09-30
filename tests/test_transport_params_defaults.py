import pytest

from quicly.configuration import load_transport_parameters, TP_REGISTRY
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
    defaults = load_transport_parameters().to_id_value_map()
    tlv = encode_transport_params([], include_defaults=True)
    decoded = _decode_map(tlv)

    # All integer defaults must be present; false flags must omit length; true flags must be present with zero-length
    for pid, default_value in defaults.items():
        if isinstance(default_value, bool):
            assert pid in decoded, f"flag {pid} missing"
            if default_value:
                assert decoded[pid] is True
            else:
                assert decoded[pid] is False
        else:
            assert pid in decoded, f"int param {pid} missing"
            assert decoded[pid] == default_value, f"int param {pid} value mismatch"

def test_include_defaults_with_override_last_wins():
    defaults = load_transport_parameters().to_id_value_map()
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
    defaults = load_transport_parameters().to_id_value_map()
    tlv = encode_transport_params([], include_defaults=True)
    cf = ConfigFrame(decode_transport_params(tlv))
    body = cf.encode()
    parsed, used = ConfigFrame.decode(body)
    assert used == len(body)

    by_id = {tp.param_id: tp.value for tp in parsed.transport_parameters}
    for pid, dv in defaults.items():
        assert pid in by_id
        if isinstance(dv, bool):
            if dv:
                assert by_id[pid] is True
            else:
                assert by_id[pid] is False
        else:
            assert by_id[pid] == dv

def test_as_list():
    tp = load_transport_parameters(defaults_path="transport_defaults.toml",
                                   override_path="tp_test.toml",
                                   runtime_overrides={"initial_max_data": 65536})

    wire_all = tp.as_list(exclude_defaults=False)  # full set
    assert len(wire_all) == len(TP_REGISTRY)

    wire_min = tp.as_list(exclude_defaults=True)  # only diffs vs TOML defaults
    assert len(wire_min) == 3

    tp = load_transport_parameters()
    tp.max_udp_payload_size = 24000
    no_defaults = tp.as_list(exclude_defaults=True)
    assert len(no_defaults) == 1

    assert tp.initial_padding_target == 1200  # default value
    tp.update({"initial_padding_target": 2400})
    assert tp.initial_padding_target == 2400