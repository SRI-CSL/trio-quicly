#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

import json
import logging
import uuid
from logging.config import dictConfig
from pathlib import Path
import structlog
import trio
from typing import Any

from .qlog import QlogEvent, QlogName, QlogCategory, Vantage

QLOG_VERSION = "0.3"
_QLOG_START: float | None = None
QUIC_LOG = "qlog"
_logger = None
_collector = None
pre_chain = [
    # Add the log level and producer to the event_dict if the log entry is not from structlog.
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
]
config_dict = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s,%(msecs)06d - [%(levelname)-7s][%(threadName)-12.12s] : %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'quicly-formatter': {
            '()': structlog.stdlib.ProcessorFormatter,
            'processor': structlog.dev.ConsoleRenderer(colors=True),
            'foreign_pre_chain': pre_chain,
        },
        'jsonformatter': {
            '()': structlog.stdlib.ProcessorFormatter,
            'processor': structlog.processors.JSONRenderer(sort_keys=False),
            'foreign_pre_chain': pre_chain,
        },
    },
    'handlers': {
        'structlog-console': {
            'level': 'DEBUG',  # TODO: make this configurable
            'formatter': 'quicly-formatter',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',  # Default is stderr
        },
    },
    'loggers': {
        QUIC_LOG: {
            'handlers': ['structlog-console'],
            'level': 'DEBUG',
            'propagate': False
        },
    },
}

def _trio_time_ms() -> int:
    global _QLOG_START
    if _QLOG_START is None:
        raise ValueError("QLog not initialized")
    return int((trio.current_time() - _QLOG_START) * 1000)

def add_qlog_time(_, __, event_dict):
    # relative time in milliseconds since trace start
    event_dict["time"] = _trio_time_ms()
    return event_dict

class QlogMemoryCollector:
    """
    structlog processor that groups events by 'odcid' and can dump
    each group as NDJSON (one event JSON object per line).
    """
    def __init__(self, trace_key: str = "odcid"):
        self.trace_key = trace_key
        self._by_trace: dict[str, list[QlogEvent]] = {}

    def __call__(self, _logger, _method, event_dict: dict):
        ev = dict(event_dict)  # shallow copy
        tid = ev.get(self.trace_key, "unknown")
        # TODO: if not "unknown", also parse out vantage for QlogTrace()?
        qev = self._to_qlog_event(ev)
        if qev is not None:
            events = self._by_trace.get(tid, [])
            events.append(qev)
            self._by_trace[tid] = events
        return event_dict  # keep pipeline going

    @staticmethod
    def _to_qlog_event(ev: dict) -> QlogEvent | None:
        try:
            name = QlogName.from_str(ev.pop("name", ev.pop("event", "event")))
            category = QlogCategory.from_str(ev.pop("category", "unknown"))
        except ValueError:
            return None  # could not parse this log event into Qlog format: skip
        t = ev.pop("time", 0.0)
        data = ev.pop("data", {})
        ev.pop("level", None)  # drop console-only metadata
        return QlogEvent(t, category, name, data)

    def get_qlogs(self) -> dict[str, list[QlogEvent]]:
        return {k: v for k, v in self._by_trace.items() if k != "unknown"}

    def dump_ndjson_per_trace(self, dir_path: Path, filename: str = "{odcid}.qlog") -> list[str]:
        """
        Write one file per ODCID, NDJSON (one event per line).
        Returns list of written paths.
        """
        dir_path.mkdir(parents=True, exist_ok=True)
        written = []
        for tid, events in self.get_qlogs().items():
            file_path = dir_path / filename.format(odcid=tid)
            with file_path.open("w", encoding="utf-8") as f:
                for e in events:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            written.append(file_path)
        return written

def init_logging() -> tuple[Any, None] | tuple[Any, QlogMemoryCollector]:
    global _logger, _collector
    if _logger is not None:
        return _logger, _collector

    # MUST be called from within a running Trio context so current_time() is valid.
    global _QLOG_START
    if _QLOG_START is None:
        _QLOG_START = trio.current_time()

    # configure logging:
    dictConfig(config_dict)
    _collector = QlogMemoryCollector(trace_key="odcid_hex")
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            add_qlog_time,                               # adds "time" (ms since start)
            _collector,                                  # collect all logged events in memory for QLOG file(s)
            structlog.stdlib.filter_by_level,            # filter here for other processors
            structlog.processors.StackInfoRenderer(),    # Include the stack when stack_info=True
            structlog.processors.format_exc_info,        # Include the exception when exc_info=True
            structlog.processors.UnicodeDecoder(),       # Decodes the unicode values in any kv pairs
            structlog.processors.TimeStamper(fmt='%Y-%m-%d %H:%M:%S,%f'),
            # this must be the last one if further customizing formats below...
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,  # <-- NO make_filtering_bound_logger to let events pass through
        cache_logger_on_first_use=True,
    )

    _logger = structlog.get_logger(QUIC_LOG)
    _logger.info(f"Initialized logging for QUIC-LY")
    return _logger, _collector

def make_qlog(vantage: Vantage, category: str, group_id: str | None = None):
    """
    vantage: "client" or "server"
    group_id: stable ID to group multi-connection traces (UUID recommended)
    """
    return (
        structlog.get_logger(QUIC_LOG).bind(vantage=vantage,
                                            category=category,
                                            group_id=group_id or str(uuid.uuid4()))
    )
