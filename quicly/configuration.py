#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from dataclasses import dataclass, field, asdict, replace, is_dataclass
from functools import lru_cache
import os
from pathlib import Path
import sys
from typing import *

SMALLEST_MAX_DATAGRAM_SIZE = 1200

# --- TOML reader (stdlib on 3.11+, tomli fallback) ---
if sys.version_info >= (3, 11):
    import tomllib  # pyright: ignore[reportMissingImports]
    from importlib.resources import files as ir_files
else:
    import tomli as tomllib  # type: ignore[no-redef]
    from importlib_resources import files as ir_files

# ---------- helpers ----------
def _deep_update(dst: dict, src: Mapping) -> dict:
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), dict):
            _deep_update(dst[k], v)
        else:
            dst[k] = v
    return dst

def _coerce_env(val: str) -> Any:
    s = val.strip()
    low = s.lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        if s.isdecimal() or (s.startswith("-") and s[1:].isdecimal()):
            return int(s)
        return float(s)
    except ValueError:
        return s

def _apply_env_overrides(target: dict, *, prefix: str = "QUICLY_TP__", sep: str = "__") -> None:
    """
    Populate `target` with environment overrides. Keys are lowercased.
    Examples:
      QUICLY_TP__INITIAL_MAX_DATA=99999
      QUICLY_TP__DISABLE_ACTIVE_MIGRATION=true
    Nested paths (with __) are supported but for TP we expect flat keys.
    """
    n = len(prefix)
    for key, val in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[n:].split(sep)
        node = target
        for part in parts[:-1]:
            node = node.setdefault(part.lower(), {})
        node[parts[-1].lower()] = _coerce_env(val)

def _load_toml(path: str) -> dict:
    """
    Load TOML from:
      1) absolute path or existing CWD-relative path
      2) package resource next to this module (preferred for installed/wheel)
      3) filesystem path relative to this file
    """
    if path is None:
        return {}

    # 1) absolute or CWD-relative
    p = Path(path)
    if p.is_absolute() or p.exists():
        with p.open("rb") as f:
            return tomllib.load(f)

    # 2) package resource (works under Poetry/pytest/wheels)
    pkg = __package__ or __name__.rpartition(".")[0]
    try:
        res = ir_files(pkg).joinpath(path)  # e.g., "transport_defaults.toml"
        if res.is_file():
            data = res.read_bytes()
            return tomllib.loads(data.decode("utf-8"))
    except Exception:
        pass

    # 3) relative to this file
    here = Path(__file__).resolve().parent
    cand = here / path
    if cand.exists():
        with cand.open("rb") as f:
            return tomllib.load(f)

    raise FileNotFoundError(
        f"Could not locate TOML file {path!r} in CWD, as package resource under {pkg!r}, "
        f"or alongside {__file__}"
    )


# === QUIC-LY Transport Parameters (CONFIG / CONFIG-ACK) =====================
# TODO: Linda: make sure that overriding max_datagram_frame_size > 0 needs to be also > MAX_UDP_PAYLOAD_SIZE!
#  For most uses of DATAGRAM frames,
#  it is RECOMMENDED to send a value of 65535 in the max_datagram_frame_size transport parameter to indicate that
#  this endpoint will accept any DATAGRAM frame that fits inside a QUIC packet.

# --- Transport Parameter ID registry (spec-aligned) ---
# tuple: (dataclass_field_name, PARAM_ID, is_flag)
TP_REGISTRY: list[tuple[str, int, bool]] = [
    ("max_idle_timeout_ms",                 0x01,  False),
    ("max_udp_payload_size",                0x03,  False),
    ("initial_max_data",                    0x04,  False),
    ("initial_max_stream_data_bidi_local",  0x05,  False),
    ("initial_max_stream_data_bidi_remote", 0x06,  False),
    ("initial_max_stream_data_uni",         0x07,  False),
    ("initial_max_streams_bidi",            0x08,  False),
    ("initial_max_streams_uni",             0x09,  False),
    ("ack_delay_exponent",                  0x0a,  False),
    ("max_ack_delay_ms",                    0x0b,  False),
    ("disable_active_migration",            0x0c,  True),   # flag: presence => true
    ("active_connection_id_limit",          0x0e,  False),
    ("max_datagram_frame_size",             0x20,  False),  # RFC 9221
    ("initial_padding_target",              0x173, False),  # QUIC-LY
]

# Fast lookup maps
TRANSPORT_PARAM_ID_BY_FIELD: dict[str, int] = {name: pid for name, pid, _ in TP_REGISTRY}
TRANSPORT_PARAM_FIELD_BY_ID: dict[int, str] = {pid: name for name, pid, _ in TP_REGISTRY}
TRANSPORT_PARAM_IS_FLAG:     dict[str, bool] = {name: is_flag for name, _, is_flag in TP_REGISTRY}

# ---------- Transport Parameters ----------
@dataclass
class TransportParameters:
    # No Python defaults here: construct from TOML (and overlays)
    max_idle_timeout_ms: int
    max_udp_payload_size: int
    initial_max_data: int
    initial_max_stream_data_bidi_local: int
    initial_max_stream_data_bidi_remote: int
    initial_max_stream_data_uni: int
    initial_max_streams_bidi: int
    initial_max_streams_uni: int
    ack_delay_exponent: int
    max_ack_delay_ms: int
    disable_active_migration: bool
    active_connection_id_limit: int
    max_datagram_frame_size: int
    initial_padding_target: int

    def to_config_map(self) -> dict[str, int | bool]:
        """
        Return a plain dict suitable for building CONFIG/CONFIG-ACK TLVs
        """
        return asdict(self)

    def to_id_value_map(self) -> dict[int, int | bool]:
        """
        Convert this TransportParameters instance into {PARAM_ID: value_or_flag}.
        Flags: include PARAM_ID with value True iff the flag is set (presence => true).
        Integers: include PARAM_ID with the integer value (will be varint-encoded by the TLV layer).
        Omit False flags entirely.
        """
        d = self.to_config_map()
        out: dict[int, int | bool] = {}
        for name, pid, is_flag in TP_REGISTRY:
            val = d.get(name)
            if is_flag:
                if bool(val):
                    out[pid] = True  # TLV encoder will emit VALUE_LEN=0 for flags
            else:
                out[pid] = int(val)
        return out

    def as_list(self, exclude_defaults: bool = False) -> list[tuple[int, int | bool]]:
        """
        Convert this TransportParameters to a stable, spec-ordered list of (param_id, value).
        If exclude_defaults=True, compare against TOML defaults and omit entries that match
        the defaults.
        """
        current = self.to_config_map()
        base = None
        if exclude_defaults:
            try:
                base = asdict(_tp_defaults_from_toml())  # TOML-driven baseline
            except FileNotFoundError:
                base = None  # fall back to including all if defaults missing

        out: list[tuple[int, int | bool]] = []
        for name, param_id, is_flag in TP_REGISTRY:
            val = current[name]
            if is_flag:
                bval = bool(val)
                if exclude_defaults and base is not None:
                    if bool(base.get(name, bval)) == bval:
                        continue
                out.append((param_id, bval))
            else:
                ival = int(val)
                if exclude_defaults and base is not None:
                    if int(base.get(name, ival)) == ival:
                        continue
                out.append((param_id, ival))
        return out

    def update(self, new_params: Mapping[Union[str, int], int | bool]) -> bool:
        """
        Update transport parameters in place.
        :param new_params: Dictionary of transport parameter names or IDs and their new values.
        :return: True iff at least one value changed.
        """
        if new_params is None:
            return False
        changed = False
        for key, raw in new_params.items():
            # Allow enum keys or field-name strings
            name = str.lower(key.name) if hasattr(key, "name") else str(key)

            if not hasattr(self, name):
                continue  # ignore unknown keys

            current = getattr(self, name)
            # Normalize the incoming value to the attribute's type
            if isinstance(current, bool):
                new_val = bool(raw)
            elif isinstance(current, int):
                # Accept ints (and, if given, cast bools to ints explicitly)
                new_val = int(raw)
            else:
                # Fallback (shouldn't happen for this dataclass)
                new_val = raw

            if current != new_val:
                setattr(self, name, new_val)
                changed = True
        return changed


def load_transport_parameters(
    *,
    defaults_path: str = "transport_defaults.toml",
    override_path: Optional[str] = None,             # e.g., "tp_test.toml"
    env_prefix: str = "QUICLY_TP__",
    runtime_overrides: Optional[Mapping[str, Any]] = None,
) -> TransportParameters:
    """
    Load TPs as: transport_defaults.toml → (optional) override_path → ENV (QUICLY_TP__) → runtime_overrides.
    If none of override_path/ENV/runtime are provided, returns exactly the defaults from TOML.
    """
    # 1) Required defaults from version-controlled TOML
    base = _load_toml(defaults_path)
    # Expect the file to have either a top-level table or a [transport] table.
    if "transport" in base:
        cfg = dict(base["transport"])
    else:
        cfg = dict(base)

    # 2) Optional partial override TOML (e.g., tp_test.toml)
    if override_path:
        ov = _load_toml(override_path)
        _deep_update(cfg, ov.get("transport", ov))

    # 3) ENV overlay (flat keys; we lowercase on the Python side)
    env_cfg: dict[str, Any] = {}
    _apply_env_overrides(env_cfg, prefix=env_prefix)  # ← call with env_cfg
    if env_cfg:
        _deep_update(cfg, env_cfg)

    # 4) Runtime overlay (dict from call-site)
    if runtime_overrides:
        _deep_update(cfg, runtime_overrides)

    # Normalize keys to what the dataclass expects (lowercase already above)
    return TransportParameters(**cfg)

@lru_cache(maxsize=1)
def _tp_defaults_from_toml(path: str = "transport_defaults.toml") -> "TransportParameters":
    d = _load_toml(path)
    # accept either a flat file or a [transport] table
    cfg = d.get("transport", d)
    return TransportParameters(**cfg)

def _apply_mapping_to_dataclass(dc_obj, mapping: Mapping[str, Any]) -> Any:
    """
    Return a new dataclass instance with only the intersecting fields updated.
    Unknown keys are ignored. Nested dataclasses are not recursed here
    (we handle transport separately).
    """
    if not is_dataclass(dc_obj):
        raise TypeError("dc_obj must be a dataclass instance")
    cur = asdict(dc_obj)
    # Strictly update only known fields
    for k, v in mapping.items():
        key = k.strip()
        # case-insensitive match for convenience
        # Prefer exact match; fall back to lowercased lookup
        if key in cur:
            cur[key] = v
        else:
            lk = key.lower()
            # find any field whose lower() matches
            for field_name in cur.keys():
                if field_name.lower() == lk:
                    cur[field_name] = v
                    break
    return type(dc_obj)(**cur)

def _env_to_mapping(prefix: str) -> dict[str, Any]:
    """
    Collect environment variables under `prefix` into a flat mapping using
    lowercased keys, e.g. QUICKLY__LOGGING_LEVEL=DEBUG -> {"logging_level": "DEBUG"}.
    For nested paths using __ separators, we only care about the final key
    (since we don't have nested top-level in QuicConfiguration itself).
    """
    n = len(prefix)
    out: dict[str, Any] = {}
    for key, val in os.environ.items():
        if not key.startswith(prefix):
            continue
        # Take the last segment for the key (QUICKLY__FOO__BAR -> "bar")
        parts = key[n:].split("__")
        leaf = parts[-1].strip().lower()
        out[leaf] = _coerce_env(val)
    return out

def _apply_transport_overrides(tp, overrides: Mapping[str, Any]) -> Any:
    """
    Return a new TransportParameters reflecting the provided overrides.
    Unknown keys are ignored (by intersecting with existing fields).
    """
    return _apply_mapping_to_dataclass(tp, overrides)


@dataclass
class QuicConfiguration:
    # top-level fields (separate from QUIC-LY Transport Parameters)
    logging_level: str = "INFO"
    ipv6: bool = False
    is_client: bool = True
    max_ack_intervals: int = 10

    transport_local: TransportParameters = field(default_factory=lambda: load_transport_parameters())
    transport_peer: Optional[TransportParameters] = None  # always None at load

    @classmethod
    def load(
        cls,
        *,
        toml_path: Optional[str] = None,
        env_prefix_top: str = "QUICKLY__",       # top-level ENV (per your request)
        env_prefix_tp: str = "QUICLY_TP__",      # transport ENV (unchanged)
        runtime_overrides: Optional[Mapping[str, Any]] = None,
    ) -> "QuicConfiguration":
        """
        Build a configuration as:
          1) Python defaults (top-level) + TransportParameters from transport_defaults.toml
          2) TOML file overrides (top-level and [transport]) if provided
          3) ENV overrides (QUICKLY__ for top-level, QUICLY_TP__ for transport)
          4) runtime_overrides mapping; nested {"transport": {...}} applies to transport
        Unknown keys are ignored at each step. transport_peer remains None.
        """
        # 1) Baseline defaults
        conf = cls()

        # 2) Optional TOML file with overrides
        if toml_path:
            toml_data = _load_toml(toml_path)

            # top-level: only keys that match QuicConfiguration fields (excluding transport_peer)
            top_overrides = {
                k: v for k, v in toml_data.items()
                if k != "transport" and hasattr(conf, k)
            }
            if top_overrides:
                conf = replace(conf, **top_overrides)

            # [transport] section
            if isinstance(toml_data.get("transport"), Mapping):
                conf.transport_local = _apply_transport_overrides(conf.transport_local, toml_data["transport"])

        # 3) ENV overrides
        # 3a) Top-level via QUICKLY__*
        top_env = _env_to_mapping(env_prefix_top)
        if top_env:
            # only apply keys that exist on QuicConfiguration (ignore unknowns)
            valid = {k: v for k, v in top_env.items() if hasattr(conf, k)}
            if valid:
                conf = replace(conf, **valid)

        # 3b) Transport via QUICLY_TP__*
        tp_env = _env_to_mapping(env_prefix_tp)
        if tp_env:
            conf.transport_local = _apply_transport_overrides(conf.transport_local, tp_env)

        # 4) runtime overrides
        if runtime_overrides:
            # split transport and top-level
            ro_tp = None
            if "transport" in runtime_overrides and isinstance(runtime_overrides["transport"], Mapping):
                ro_tp = runtime_overrides["transport"]

            ro_top = {
                k: v for k, v in runtime_overrides.items()
                if k != "transport" and hasattr(conf, k)
            }
            if ro_top:
                conf = replace(conf, **ro_top)
            if ro_tp:
                conf.transport_local = _apply_transport_overrides(conf.transport_local, ro_tp)

        # Ensure peer stays None at load time
        conf.transport_peer = None
        return conf

    def set_peer_transport(self, peer_tp: Mapping[str, Any]) -> None:
        """
        Call right after handshake: set peer’s effective parameters.
        Unknown fields are ignored; missing fields use our current local settings.
        """
        base = asdict(self.transport_local)
        base.update({k: v for k, v in peer_tp.items() if k in base})
        self.transport_peer = TransportParameters(**base)

    # Convenience for your TLV/path code
    def local_tp_map(self) -> dict[str, int | bool]:
        return self.transport_local.to_config_map()

    def peer_tp_map(self) -> Optional[dict[str, int | bool]]:
        return None if self.transport_peer is None else self.transport_peer.to_config_map()
