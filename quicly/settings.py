#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
from dataclasses import dataclass, field
from typing import *

@dataclass
class Settings:
    logging: dict[str, Any]
    network: dict[str, Any]
    transport_local: dict[str, Any]     # what you will offer/use
    transport_peer: dict[str, Any] = field(default_factory=dict)  # filled after handshake
    endpoint: dict[str, Any] = field(default_factory=dict)        # e.g., is_client, connect host/port

    @classmethod
    def from_dict(cls, cfg: dict) -> "Settings":
        return cls(
            logging=cfg.get("logging", {}),
            network=cfg.get("network", {}),
            transport_local=cfg.get("transport", {}),
        )

    def set_runtime_endpoint(self, *, is_client: bool, host: str | None = None, port: int | None = None):
        self.endpoint.update({"is_client": is_client})
        if host is not None: self.endpoint["host"] = host
        if port is not None: self.endpoint["port"] = port

    def set_peer_transport(self, peer_tp: dict[str, Any]):
        """Call this right after handshake when the peer's TP are known."""
        self.transport_peer = dict(peer_tp)
