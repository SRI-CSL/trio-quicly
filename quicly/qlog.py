#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
from dataclasses import dataclass
from enum import Enum
import json
from typing import *

# QLog drafts:
#   - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-02
#   - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events

class QlogItem(Enum):

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, s: str) -> "QlogItem":
        """
        Parse a qlog item name from common forms:
        - exact qlog values: "packet_sent"
        - enum-like: "PACKET_SENT"
        - hyphen/space variants: "packet-sent", "packet sent"
        """
        norm = s.strip().lower().replace("-", "_").replace(" ", "_")
        # match by value
        for m in cls:
            if m.value == norm:
                return m
        # also allow enum member names
        name = norm.upper()
        if name in cls.__members__:
            return cls[name]
        raise ValueError(f"Unknown Qlog Item: {s!r}")

class QlogCategory(QlogItem):
    CONNECTIVITY = "connectivity"
    TRANSPORT = "transport"
    RECOVERY = "recovery"

class QlogName(QlogItem):
    # Transport and Connectivity
    PACKET_SENT             = "packet_sent"
    PACKET_RECEIVED         = "packet_received"
    PACKET_DROPPED          = "packet_dropped"
    PACKET_LOST             = "packet_lost"
    ACK_SENT                = "ack_sent"
    ACK_RECEIVED            = "ack_received"
    PARAMETERS_SET          = "parameters_set"
    STATE_UPDATED           = "state_updated"            # connectivity:state_updated
    PATH_INITIALIZED        = "path_initialized"
    PATH_MTU_UPDATED        = "path_mtu_updated"
    # Recovery
    METRICS_UPDATED         = "metrics_updated"          # recovery:metrics_updated
    CONGESTION_STATE_UPDATED= "congestion_state_updated" # recovery:congestion_state_updated
    TIMER_SET               = "timer_set"
    TIMER_EXPIRED           = "timer_expired"

    @classmethod
    def from_str(cls, s: str) -> "QlogName":
        """
        Accepts:
          - "packet_sent", "PACKET_SENT", "packet-sent", "packet sent"
          - with optional category prefixes:
            "transport:packet_sent", "recovery.metrics_updated", "CONNECTIVITY/PACKET_LOST"
        """
        raw = s.strip()
        # Normalize common separators for an optional "<category><sep><event>" form
        tmp = raw.replace("/", ":").replace(".", ":")
        if ":" in tmp:
            _, ev = tmp.split(":", 1)  # ignore the category part
        else:
            ev = tmp
        norm = ev.strip().lower().replace("-", "_").replace(" ", "_")
        # match by value
        for m in cls:
            if m.value == norm:
                return m
        # also allow enum member names
        name = norm.upper()
        if name in cls.__members__:
            return cls[name]
        raise ValueError(f"Unknown Qlog Event: {s!r}")

@dataclass
class QlogEvent:
    time: float
    category: QlogCategory
    name: QlogName
    data: dict[str, Any]

    def __str__(self):
        return f'{{"time":{self.time},"name":{self.category}:{self.name},' + \
            f'"data":{json.dumps(self.data, separators=(",", ":"), ensure_ascii=False, sort_keys=False)}}}'

    def __repr__(self):
        return str(self)

Vantage = Literal["client", "server"]

@dataclass
class QlogTrace:
    odcid_hex: str
    vantage: Vantage
    events: List[QlogEvent]

# def start_file_logging() -> None:
#     """
#     Once we know our role ("client" or "server") we can start logging to file with name "quicly_server.qlog" in QLOG
#     format.
#     TODO: figure out how to preamble log file with
#       {
#         "qlog_format": "JSON",
#         "qlog_version": QLOG_VERSION,
#         "traces": [
#     and then end properly when closing the log file with:
#         ]
#       }
#     """
#     log_dir = Path.cwd()
#     if log_dir:  # TODO: test for writeable!
#         log_dir.mkdir(parents=True, exist_ok=True)
#         quicly_logger = structlog.get_logger(QUIC_LOG)
#         file_handler = RotatingFileHandler(filename=log_dir / f"quicly_{'server'}.{QUIC_LOG}", mode="w")
#         file_handler.setFormatter(structlog.stdlib.ProcessorFormatter(
#             processor=structlog.processors.JSONRenderer(sort_keys=False)))  # keep QLOG order of JSON keys
#         quicly_logger.addHandler(file_handler)

# def configure_qlog(path: str = "trace.qlog", level: int = logging.INFO) -> None:
#     """
#     Configure qlog output as NDJSON (one JSON object per line).
#     MUST be called from within a running Trio context so current_time() is valid.
#
#     When the qlog group_id field is used, it is recommended to use QUIC's Original Destination Connection ID (ODCID,
#     the CID chosen by the client when first contacting the server), as this is the only value that does not change
#     over the course of the connection and can be used to link more advanced QUIC packets (e.g., Retry,
#     Version Negotiation) to a given connection. Similarly, the ODCID should be used as the qlog filename or file
#     identifier, potentially suffixed by the vantagepoint type (For example, abcd1234_server.qlog would contain the
#     server-side trace of the connection with ODCID abcd1234).
#     """
#     global _QLOG_START
#     if _QLOG_START is None:
#         _QLOG_START = trio.current_time()
#
#     f = open(path, "a", buffering=1, encoding="utf-8", newline="\n")  # line-buffered
#
#     structlog.configure(
#         processors=[
#             add_qlog_time,                               # adds "time" (ms since start)
#             structlog.processors.EventRenamer("name"),   # "event" -> "name"
#             structlog.processors.JSONRenderer(sort_keys=False),
#         ],
#         wrapper_class=structlog.make_filtering_bound_logger(level),
#         logger_factory=structlog.WriteLoggerFactory(file=f),
#         cache_logger_on_first_use=True,
#     )

# class QuiclyLoggerTrace:
#     """
#     A QUIC-LY event trace.
#
#     Events are logged in the format defined by qlog.
#     See:
#     - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-02
#     - https://datatracker.ietf.org/doc/html/draft-marx-quic-qlog-quic-events
#     """
#
#     def __init__(self, *, is_client: bool, odcid: bytes) -> None:
#         self._odcid = odcid
#         self._events: Deque[Dict[str, Any]] = deque()
#         self._vantage_point = {
#             "name": "trio-quicly",
#             "type": "client" if is_client else "server",
#         }
#
#     # TODO: QUIC-LY
#     # def encode_ack_frame(self, ranges: RangeSet, delay: float) -> Dict:
#     #     return {
#     #         "ack_delay": self.encode_time(delay),
#     #         "acked_ranges": [[x.start, x.stop - 1] for x in ranges],
#     #         "frame_type": "ack",
#     #     }
#
#     # CORE
#
#     def log_event(self, *, category: str, event: str, data: Dict) -> None:
#         self._events.append(add_qlog_time({
#             "data": data,
#             "name": category + ":" + event,
#         }))
#
#     def to_dict(self) -> Dict[str, Any]:
#         """
#         Return the trace as a dictionary which can be written as JSON.
#         """
#         return {
#             "common_fields": {
#                 "ODCID": hexdump(self._odcid),
#             },
#             "events": list(self._events),
#             "vantage_point": self._vantage_point,
#         }
