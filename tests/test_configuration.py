#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from quicly.configuration import QuicConfiguration, load_transport_parameters
from quicly.frame import (
    TransportParameter,
    encode_transport_params,
    decode_transport_params,
    ConfigFrame,
)


# def test_datagram_configuration():
#     config = QuicConfiguration()
#     assert config.transport_local.max_datagram_frame_size == 0
#     transport_parameters = {TransportParameterType.MAX_DATAGRAM_FRAME_SIZE : 1200}  # add DATAGRAM support
#     update_config(config, transport_parameters)
#     assert config.transport_local.max_datagram_frame_size == 1200

def test_transport_parameter_defaults():
    # Just defaults from transport_defaults.toml:
    tp = load_transport_parameters()
    assert tp.max_udp_payload_size == 65527
    tp_dict = tp.to_config_map()
    assert tp_dict["max_udp_payload_size"] == 65527

    # With a partial override file (e.g., tp_test.toml):
    tp = load_transport_parameters(
        defaults_path="transport_defaults.toml",
        override_path="tp_test.toml",
    )
    assert tp.max_idle_timeout_ms == 30000

def _decode_map(tlv: bytes):
    out = {}
    for tp in decode_transport_params(tlv):
        out[tp.param_id] = tp.value
    return out

def _is_flag_default(pid, val):
    return isinstance(val, bool)

def test_include_defaults_emits_expected_set():
    defaults = load_transport_parameters()
    tlv = encode_transport_params([], include_defaults=True)
    decoded = _decode_map(tlv)

    # All integer defaults must be present; false flags must omit length; true flags must be present with zero-length
    for pid, default_value in defaults.as_list():
        if isinstance(default_value, bool):
            assert pid in decoded, f"flag {pid} missing"
            if default_value is True:
                assert decoded[pid] is True
            else:
                assert decoded[pid] is False
        else:
            assert pid in decoded, f"int param {pid} missing"
            assert decoded[pid] == default_value, f"int param {pid} value mismatch"
