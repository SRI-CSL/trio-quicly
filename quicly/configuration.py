#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from dataclasses import dataclass, field, asdict, replace, is_dataclass, fields
from functools import lru_cache
from importlib.resources import files as ir_files  # py311+
import os
from pathlib import Path
import tomllib  # py311+
from typing import *

# ----- Spec-aligned TP registry -----
# (name, param_id, is_flag)
TP_REGISTRY: list[tuple[str, int, bool]] = [
    ("max_idle_timeout", 0x01, False),
    ("max_udp_payload_size", 0x03, False),
    ("initial_max_data", 0x04, False),
    ("initial_max_stream_data_bidi_local", 0x05, False),
    ("initial_max_stream_data_bidi_remote", 0x06, False),
    ("initial_max_stream_data_uni", 0x07, False),
    ("initial_max_streams_bidi", 0x08, False),
    ("initial_max_streams_uni", 0x09, False),
    ("ack_delay_exponent", 0x0a, False),
    ("max_ack_delay", 0x0b, False),
    ("disable_active_migration", 0x0c, True),
    ("active_connection_id_limit", 0x0e, False),
    ("max_datagram_frame_size", 0x20, False),
    ("initial_padding_target", 0x173, False),
]
TP_ID_BY_NAME = {n: i for n, i, _ in TP_REGISTRY}
TP_NAME_BY_ID = {i: n for n, i, _ in TP_REGISTRY}
TP_IS_FLAG = {n: f for n, _, f in TP_REGISTRY}


# ----- Small utilities -----
def _deep_update(dst: dict, src: Mapping) -> dict:
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), dict):
            _deep_update(dst[k], v)
        else:
            dst[k] = v
    return dst


def _coerce_scalar(s: str) -> Any:
    t = s.strip()
    low = t.lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        if t.isdecimal() or (t.startswith("-") and t[1:].isdecimal()):
            return int(t)
        return float(t)
    except ValueError:
        return t


def env_to_mapping(prefix: str, sep: str = "__") -> dict[str, Any]:
    """
    QUICKLY__LOGGING_LEVEL=DEBUG      -> {"logging_level": "DEBUG"}
    QUICLY_TP__INITIAL_MAX_DATA=65536 -> {"initial_max_data": 65536}
    """
    n = len(prefix)
    out: dict[str, Any] = {}
    for k, v in os.environ.items():
        if not k.startswith(prefix):
            continue
        parts = k[n:].split(sep)
        key = parts[-1].strip().lower()
        out[key] = _coerce_scalar(v)
    return out


# def _update_dc(dc_obj, mapping: Mapping[str, Any], *, casefold=True, ignore_unknown=True):
#     """Return a new dataclass with overlap in fields updated."""
#     if not is_dataclass(dc_obj):
#         raise TypeError("dc_obj must be a dataclass instance")
#     cur = asdict(dc_obj)
#     keys = list(cur.keys())
#
#     def set_key(k: str, v: Any):
#         if k in cur:
#             cur[k] = v
#             return True
#         if casefold:
#             lk = k.lower()
#             for name in keys:
#                 if name.lower() == lk:
#                     cur[name] = v
#                     return True
#         return False
#
#     for k, v in mapping.items():
#         if not set_key(k, v) and not ignore_unknown:
#             raise KeyError(f"Unknown field: {k}")
#     return type(dc_obj)(**cur)


# ----- Robust TOML loader (CWD, absolute, or package resource) -----
def _load_toml(path: str) -> dict:
    """
    Load TOML from:
      1) absolute path or existing CWD-relative path
      2) package resource next to this module (preferred for installed/wheel)
      3) filesystem path relative to this file
    """
    p = Path(path)
    if p.is_absolute() or p.exists():
        with p.open("rb") as f:
            return tomllib.load(f)
    pkg = __package__ or __name__.rpartition(".")[0]
    try:
        res = ir_files(pkg).joinpath(path)
        if res.is_file():
            data = res.read_bytes()
            return tomllib.loads(data.decode("utf-8"))
    except Exception:
        pass
    here = Path(__file__).resolve().parent / path
    if here.exists():
        with here.open("rb") as f:
            return tomllib.load(f)
    raise FileNotFoundError(path)


# ----- Transport Parameters -----
# TODO: Linda: make sure that overriding max_datagram_frame_size > 0 needs to be also > MAX_UDP_PAYLOAD_SIZE!
#  For most uses of DATAGRAM frames,
#  it is RECOMMENDED to send a value of 65535 in the max_datagram_frame_size transport parameter to indicate that
#  this endpoint will accept any DATAGRAM frame that fits inside a QUIC packet.

@dataclass
class TransportParameters:
    # No Python defaults: constructed from TOML
    # Ranges for int's have 2**62 is the open, maximum value for encoding varint
    max_idle_timeout: int
    max_udp_payload_size: int = field(metadata={"range": (1200, 2**62)})
    initial_max_data: int
    initial_max_stream_data_bidi_local: int
    initial_max_stream_data_bidi_remote: int
    initial_max_stream_data_uni: int
    initial_max_streams_bidi: int
    initial_max_streams_uni: int
    ack_delay_exponent: int = field(metadata={"range": (0, 21)})
    max_ack_delay: int = field(metadata={"range": (1, 2**14)})
    disable_active_migration: bool
    active_connection_id_limit: int = field(metadata={"range": (2, 2**62)})
    max_datagram_frame_size: int
    initial_padding_target: int

    @staticmethod
    def _range_validator(name: str, value: int, r: tuple[int, int]) -> None:
        if r is not None:
            lo, hi = r
            if not isinstance(value, int) or not (lo <= value < hi):
                raise ValueError(f"{name} out of range [{lo}, {hi}[: {value}")

    def __post_init__(self):
        # validate constructor values
        for name, f in self.__dataclass_fields__.items():  # type: ignore[attr-defined]
            rng = f.metadata.get("range")
            if rng is not None:
                v = getattr(self, name)
                self._range_validator(name, v, rng)

    def __setattr__(self, name, value):
        # validate on subsequent assignments
        dcfields = self.__dict__.get("__dataclass_fields__") or getattr(self, "__dataclass_fields__", {})
        f = dcfields.get(name)
        if f is not None:
            rng = f.metadata.get("range")
            if rng is not None:
                self._range_validator(name, value, rng)
        super().__setattr__(name, value)

    def to_id_value_map(self) -> dict[int, int | bool]:
        """
        Convert this TransportParameters instance into {PARAM_ID: value_or_flag}.
        """
        d = asdict(self)
        out: dict[int, int | bool] = {}
        for name, pid, is_flag in TP_REGISTRY:
            val = d[name]
            if is_flag:
                out[pid] = bool(val)
            else:
                out[pid] = int(val)
        return out

    def as_list(self, exclude_defaults: bool = False) -> list[tuple[int, int | bool]]:
        """
        Convert this TransportParameters to a stable, spec-ordered list of (param_id, value).
        If exclude_defaults=True, compare against TOML defaults and omit entries that match
        the defaults.
        """
        current = asdict(self)
        defaults = asdict(tp_defaults_from_toml())
        out: list[tuple[int, int | bool]] = []
        for name, pid, is_flag in TP_REGISTRY:
            if is_flag:
                v = bool(current[name])
                if not exclude_defaults or bool(defaults.get(name)) != v:
                    out.append((pid, v))
            else:
                iv = int(current[name])
                if not exclude_defaults or int(defaults.get(name)) != iv:
                    out.append((pid, iv))
        return out

    def update(self, new_params: dict[str | int, int | bool]) -> bool:
        """
        In-place update from a mapping keyed by field names (case-insensitive).
        Returns True if any field actually changed.
        Unknown keys are ignored.
        """
        changed = False
        for k, v in new_params.items():
            # Normalize key to a dataclass field name
            if isinstance(k, int):
                name = TP_NAME_BY_ID.get(k)
                if not name:
                    continue
            else:
                key = str(k).strip().lower()
                name = next((f.name for f in fields(self) if f.name.lower() == key), None)
                if not name:
                    continue

            # Coerce type and compare
            if TP_IS_FLAG.get(name, False):
                new_val = bool(v)
            else:
                new_val = int(v)

            old_val = getattr(self, name)
            if old_val != new_val:
                setattr(self, name, new_val)
                changed = True
        return changed


def load_transport_parameters(
        defaults_path: str = "transport_defaults.toml",
        override_path: Optional[str] = None,
        env_prefix: str = "QUICLY_TP__",
        runtime_overrides: Optional[Mapping[str, Any]] = None,
) -> TransportParameters:
    base = _load_toml(defaults_path)
    cfg = dict(base.get("transport", base))

    if override_path:
        ov = _load_toml(override_path)
        _deep_update(cfg, ov.get("transport", ov))

    env_map = env_to_mapping(env_prefix)
    if env_map:
        _deep_update(cfg, env_map)

    if runtime_overrides:
        _deep_update(cfg, runtime_overrides)

    return TransportParameters(**cfg)


@lru_cache(maxsize=1)
def tp_defaults_from_toml(path: str = "transport_defaults.toml") -> "TransportParameters":
    d = _load_toml(path)
    # accept either a flat file or a [transport] table
    cfg = d.get("transport", d)
    return TransportParameters(**cfg)


# ----- QuicConfiguration -----
@dataclass
class QuicConfiguration:
    logging_level: str = "INFO"
    ipv6: bool = False
    is_client: bool = True
    max_ack_intervals: int = 10

    # TODO: what are the semantics of receiving peer parameters? => implement effective_* functions??
    transport_local: TransportParameters = field(default_factory=lambda: load_transport_parameters())
    transport_peer: Optional[TransportParameters] = None  # set after handshake

    @classmethod
    def load(cls,
            toml_path: Optional[str] = None,
            env_prefix_top: str = "QUICKLY__",  # top-level env
            env_prefix_tp: str = "QUICLY_TP__",  # transport env
            runtime_overrides: Optional[Mapping[str, Any]] = None,
    ) -> "QuicConfiguration":
        # 1) Python defaults + TP from version-controlled TOML
        conf = cls()

        # 2) Apply TOML file (top-level keys + [transport])
        if toml_path:
            data = _load_toml(toml_path)
            top = {k: v for k, v in data.items() if k != "transport" and hasattr(conf, k)}
            if top:
                conf = replace(conf, **top)
            if isinstance(data.get("transport"), Mapping):
                conf.update_local(data["transport"])

        # 3) ENV overrides
        top_env = env_to_mapping(env_prefix_top)
        if top_env:
            top_valid = {k: v for k, v in top_env.items() if hasattr(conf, k)}
            if top_valid:
                conf = replace(conf, **top_valid)
        tp_env = env_to_mapping(env_prefix_tp)
        if tp_env:
            conf.update_local(tp_env)

        # 4) runtime overrides
        if runtime_overrides:
            ro_tp = None
            if isinstance(runtime_overrides.get("transport"), Mapping):
                ro_tp = runtime_overrides["transport"]
            ro_top = {k: v for k, v in runtime_overrides.items() if k != "transport" and hasattr(conf, k)}
            if ro_top:
                conf = replace(conf, **ro_top)
            if ro_tp:
                conf.update_local(ro_tp)

        conf.transport_peer = None
        return conf

    def _update_transport(self, overrides: dict[int | str, int | bool], target: str) -> bool:
        """
        Apply transport overrides to 'local' or 'peer'.
        - Accepts IDs or field names.
        - Mutates the chosen TP object in-place. If this updates "peer" for the first time (i.e., TPs is None) then
          seeding TPs from current "local" settings first before applying overrides.
        - Returns True iff anything changed from the prior state.
        """
        if target not in ("local", "peer"):
            raise ValueError("target must be 'local' or 'peer'")

        if overrides is None:
            return False

        if target == "local":
            return self.transport_local.update(overrides)

        # target == "peer"
        changed = False
        if self.transport_peer is None:
            # Start from the current local as baseline for the peer
            self.transport_peer = replace(self.transport_local)
            changed = True

        changed |= self.transport_peer.update(overrides)
        return changed

    def update_local(self, overrides: dict[int | str, int | bool]) -> bool:
        """
        Update local transport parameters with given overrides return whether anything has changed.
        Return False if overrides are None.
        """
        return self._update_transport(overrides, "local")

    def update_peer(self, overrides: dict[int | str, int | bool]) -> bool:
        """
        Apply given overrides to peer transport and return whether anything has changed.
        Return False if overrides are None.
        """
        return self._update_transport(overrides, "peer")

    @property
    def has_received_peer_tp(self) -> bool:
        return self.transport_peer is not None  # will be True once transport_peer set after handshake

    @property
    def effective_max_idle_timeout(self) -> float:
        if not self.has_received_peer_tp:
            return self.transport_local.max_idle_timeout
        # calculate minimum of all non-zero values:
        if self.transport_local.max_idle_timeout == 0:
            return self.transport_peer.max_idle_timeout
        if self.transport_peer.max_idle_timeout == 0:
            return self.transport_local.max_idle_timeout
        return min(self.transport_local.max_idle_timeout, self.transport_peer.max_idle_timeout)

    @property
    def peer_max_datagram_frame_size(self) -> int:
        if not self.has_received_peer_tp:
            return 0
        return self.transport_peer.max_datagram_frame_size
