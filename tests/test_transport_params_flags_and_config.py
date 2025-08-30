import pytest
from quicly.frame import (
    TransportParameter,
    encode_transport_params,
    decode_transport_params,
    encode_var_length_int,
    ConfigFrame, QuicFrame, QuicFrameType,
)
from quicly.configuration import TransportParameterType

def has_attr(obj, name):
    try:
        getattr(obj, name)
        return True
    except AttributeError:
        return False

def tlv_unknown(pid: int, value: int) -> bytes:
    vbytes = encode_var_length_int(value)
    return encode_var_length_int(pid) + encode_var_length_int(len(vbytes)) + vbytes

# --- Existing basic tests kept for continuity --------------------------------

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
    params = [TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 777)]
    tlv = encode_transport_params(params, include_defaults=False)
    decoded = decode_transport_params(tlv)
    assert len(decoded) == 1
    assert decoded[0].param_id == TransportParameterType.INITIAL_MAX_DATA
    assert decoded[0].value == 777

# --- New tests: flag semantics ------------------------------------------------

@pytest.mark.skipif(
    not hasattr(TransportParameterType, "DISABLE_ACTIVE_MIGRATION"),
    reason="Flag parameter DISABLE_ACTIVE_MIGRATION not defined in TransportParameterType"
)
def test_flag_true_is_zero_length_and_false_is_omitted():
    # True flag should produce: PID + LEN(=0) and no value bytes.
    pid = TransportParameterType.DISABLE_ACTIVE_MIGRATION
    tp_true = TransportParameter(pid, True).encode()
    assert tp_true == encode_var_length_int(pid) + encode_var_length_int(0)

    # False flag SHOULD be omitted entirely when building a TLV list.
    tlv = encode_transport_params([TransportParameter(pid, False)], include_defaults=False)
    assert tlv == encode_var_length_int(pid)

@pytest.mark.skipif(
    not hasattr(TransportParameterType, "DISABLE_ACTIVE_MIGRATION"),
    reason="Flag parameter DISABLE_ACTIVE_MIGRATION not defined in TransportParameterType"
)
def test_flag_amidst_other_params_is_parsed_correctly():
    # Build a TLV list with [unknown] + [flag true] + [known int] + [unknown]
    flag_pid = TransportParameterType.DISABLE_ACTIVE_MIGRATION
    known = TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 1000).encode()
    flag = TransportParameter(flag_pid, True).encode()
    buf = tlv_unknown(0xABCD, 7) + flag + known + tlv_unknown(0xDCBA, 9)
    decoded = decode_transport_params(buf)

    # Expect two parsed params: the flag and the known int
    by_id = {tp.param_id: tp.value for tp in decoded}
    assert by_id[flag_pid] is True
    assert by_id[TransportParameterType.INITIAL_MAX_DATA] == 1000
    # Unknowns must not appear
    assert len(decoded) == 2

# --- New tests: spec concrete example ----------------------------------------

@pytest.mark.skipif(
    not hasattr(TransportParameterType, "INITIAL_PADDING_TARGET"),
    reason="INITIAL_PADDING_TARGET not defined in TransportParameterType"
)
def test_initial_padding_target_1200_example_bytes_from_spec():
    # PARAM_ID = 0x09 ; value = 1200 => TLV: 09 02 44 B0
    pid = TransportParameterType.INITIAL_PADDING_TARGET
    tp = TransportParameter(pid, 1200)
    tlv = tp.encode()
    assert tlv == bytes.fromhex("09 02 44 B0")

    # Round-trip parse
    decoded = decode_transport_params(tlv)
    assert len(decoded) == 1
    assert decoded[0].param_id == pid
    assert decoded[0].value == 1200

# --- New tests: ConfigFrame round-trips --------------------------------------

def test_configframe_roundtrip_single_known_param():
    params = [TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 111)]
    cf = QuicFrame(QuicFrameType.CONFIG_ACK,
                   content=ConfigFrame(params))
    body = cf.encode()  # pid|len|TLV-list
    cf2, used = QuicFrame.decode(body)
    assert used == len(body)
    assert cf2.frame_type == QuicFrameType.CONFIG_ACK
    assert isinstance(cf2.content, ConfigFrame)
    assert len(cf2.content.transport_parameters) == 1
    assert cf2.content.transport_parameters[0].param_id == TransportParameterType.INITIAL_MAX_DATA
    assert cf2.content.transport_parameters[0].value == 111

@pytest.mark.skipif(
    not hasattr(TransportParameterType, "DISABLE_ACTIVE_MIGRATION"),
    reason="Flag parameter DISABLE_ACTIVE_MIGRATION not defined in TransportParameterType"
)
def test_configframe_roundtrip_mixed_flag_and_known_and_unknown():
    # Build TLV list: unknown | flag(true) | known int | unknown | duplicate known (last wins)
    tlvs = bytearray()
    tlvs += tlv_unknown(0xCAFE, 1)
    tlvs += TransportParameter(TransportParameterType.DISABLE_ACTIVE_MIGRATION, True).encode()
    tlvs += TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 222).encode()
    tlvs += tlv_unknown(0xBEEF, 3)
    tlvs += TransportParameter(TransportParameterType.INITIAL_MAX_DATA, 333).encode()  # duplicate

    cf = ConfigFrame(decode_transport_params(bytes(tlvs)))
    body = cf.encode()
    parsed, used = ConfigFrame.decode(body)
    assert used == len(body)

    by_id = {tp.param_id: tp.value for tp in parsed.transport_parameters}
    assert by_id[TransportParameterType.DISABLE_ACTIVE_MIGRATION] is True
    assert by_id[TransportParameterType.INITIAL_MAX_DATA] == 333  # last wins
    # only two known params expected
    assert len(parsed.transport_parameters) == 2
