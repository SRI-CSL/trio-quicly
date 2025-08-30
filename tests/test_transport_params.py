from quicly.frame import TransportParameter, encode_transport_params, decode_transport_params, encode_var_length_int
from quicly.configuration import TransportParameterType

def tlv_unknown(pid: int, value: int) -> bytes:
    # Encode a TLV for an unknown parameter id using QUIC varints
    vbytes = encode_var_length_int(value)
    return encode_var_length_int(pid) + encode_var_length_int(len(vbytes)) + vbytes

def test_roundtrip_known_integer_param():
    tp = TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 1_048_576)
    buf = tp.encode()
    decoded = decode_transport_params(buf)
    assert len(decoded) == 1
    assert decoded[0].param_id == TransportParameterType.INITIAL_MAX_DATA
    assert decoded[0].value == 1_048_576

def test_duplicate_last_wins():
    tp1 = TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 10)
    tp2 = TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 20)
    buf = tp1.encode() + tp2.encode()
    decoded = decode_transport_params(buf)
    assert len(decoded) == 1
    assert decoded[0].param_id == TransportParameterType.INITIAL_MAX_DATA
    assert decoded[0].value == 20

def test_unknown_param_is_ignored():
    # Use a made-up id (0xDEAD) which should not be in TransportParameterType
    unk = tlv_unknown(0xDEAD, 1234)
    decoded = decode_transport_params(unk)
    assert decoded == []

def test_mixed_known_and_unknown():
    known = TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 33).encode()
    unk1  = tlv_unknown(0xBEEF, 1)
    unk2  = tlv_unknown(0xCAFE, 2)
    buf = unk1 + known + unk2
    decoded = decode_transport_params(buf)
    assert len(decoded) == 1
    assert decoded[0].param_id == TransportParameterType.INITIAL_MAX_DATA
    assert decoded[0].value == 33

def test_encode_transport_params_include_defaults_false_only_outputs_given_params():
    # This avoids depending on QUICLY_DEFAULTS availability; set include_defaults=False
    params = [TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 777)]
    tlv = encode_transport_params(params, include_defaults=False)
    decoded = decode_transport_params(tlv)
    assert len(decoded) == 1
    assert decoded[0].param_id == TransportParameterType.INITIAL_MAX_DATA
    assert decoded[0].value == 777
