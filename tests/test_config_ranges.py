import pytest

# Prefer package import; fall back to local module
try:
    import quicly.configuration as cfg
except Exception:  # pragma: no cover
    import configuration as cfg


def _range_fields(tp_cls) -> list[tuple[str, tuple[int, int]]]:
    """Collect (field_name, (lo, hi)) for fields that define a 'range' metadata."""
    out = []
    for name, f in tp_cls.__dataclass_fields__.items():  # type: ignore[attr-defined]
        rng = f.metadata.get("range")
        if rng is not None:
            out.append((name, rng))
    return out


@pytest.mark.parametrize("field_name, rng", _range_fields(cfg.TransportParameters))
def test_transport_parameters_upper_bound_constructor_ok(field_name, rng):
    """
    Setting a value exactly -1 at the upper bound (hi) via the constructor should succeed.
    """
    lo, hi = rng
    # Start from default TOML-backed instance to avoid specifying every field:
    base = cfg.load_transport_parameters()
    data = base.to_id_value_map()  # quick way to copy current values
    # Convert id->value back to names so we can pass kwargs:
    name_map = {cfg.TP_NAME_BY_ID[pid]: v for pid, v in data.items() if pid in cfg.TP_NAME_BY_ID}
    name_map[field_name] = hi - 1
    # Build a new TP with hi at this field
    tp2 = cfg.TransportParameters(**name_map)
    assert getattr(tp2, field_name) == hi - 1


@pytest.mark.parametrize("field_name, rng", _range_fields(cfg.TransportParameters))
def test_transport_parameters_upper_bound_assignment_ok(field_name, rng):
    """
    Setting a value exactly at the upper bound (hi) via attribute assignment should succeed.
    """
    lo, hi = rng
    tp = cfg.load_transport_parameters()
    setattr(tp, field_name, hi - 1)
    assert getattr(tp, field_name) == hi - 1


@pytest.mark.parametrize("field_name, rng", _range_fields(cfg.TransportParameters))
def test_transport_parameters_above_upper_bound_rejected(field_name, rng):
    """
    Setting a value above the upper bound (hi+1) should raise and leave the value unchanged.
    """
    lo, hi = rng
    tp = cfg.load_transport_parameters()
    before = getattr(tp, field_name)
    with pytest.raises((ValueError, TypeError)):
        setattr(tp, field_name, hi)
    assert getattr(tp, field_name) == before


@pytest.mark.parametrize("field_name, rng", _range_fields(cfg.TransportParameters))
def test_quic_configuration_update_transport_respects_upper_bound(field_name, rng):
    """
    QuicConfiguration.update_transport(target='local') must honor the same bounds:
    - hi-1 is accepted and applied
    - hi raises and does not change the value
    """
    lo, hi = rng
    conf = cfg.QuicConfiguration.load()

    # Reject hi+1 and keep previous value
    before = getattr(conf.transport_local, field_name)
    with pytest.raises((ValueError, TypeError)):
        conf.update_local({field_name: hi})
    assert getattr(conf.transport_local, field_name) == before

    # Accept exactly at upper bound
    assert conf.update_local({field_name: hi - 1}) is True
    assert getattr(conf.transport_local, field_name) == hi - 1
