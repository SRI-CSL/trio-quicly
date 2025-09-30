#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
import os, sys
from typing import *

if sys.version_info >= (3, 11):
    import tomllib    # stdlib reader
else:
    import tomli as tomllib  # type: ignore[no-redef]

def _deep_update(dst: dict, src: Mapping) -> dict:
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), dict):
            _deep_update(dst[k], v)
        else:
            dst[k] = v
    return dst

def _coerce_env(val: str) -> Any:
    v = val.strip()
    if v.lower() in {"true","false"}: return v.lower() == "true"
    try:
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
        return float(v)
    except ValueError:
        return v

def _apply_env_overrides(cfg: dict, *, prefix="QUICLY__", sep="__") -> None:
    n = len(prefix)
    for k, v in os.environ.items():
        if not k.startswith(prefix): continue
        path = k[n:].split(sep)
        node = cfg
        for part in path[:-1]:
            node = node.setdefault(part.lower(), {})
        node[path[-1].lower()] = _coerce_env(v)

def load_defaults(
    path: str = "defaults.toml",
    *,
    runtime_overrides: Mapping[str, Any] | None = None,
) -> dict:
    with open(path, "rb") as f:
        cfg: dict = tomllib.load(f)

    _apply_env_overrides(cfg, prefix="QUICLY__")
    if runtime_overrides:
        _deep_update(cfg, runtime_overrides)
    return cfg
