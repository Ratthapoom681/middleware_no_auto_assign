import logging
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any


class InMemoryLogHandler(logging.Handler):
    def __init__(self, capacity: int = 300) -> None:
        super().__init__()
        self.capacity = capacity
        self._records: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        category = self._categorize(record.levelname, message)
        if category is None:
            return

        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "category": category,
        }

        with self._lock:
            self._records.appendleft(entry)

    def get_entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def _categorize(self, levelname: str, message: str) -> str | None:
        lowered = message.lower()
        if levelname in {"ERROR", "CRITICAL"}:
            return "error"

        if "sent to defectdojo" in lowered or "creating new defectdojo finding" in lowered:
            return "defectdojo"

        return None


_handler = InMemoryLogHandler()
_installed = False


def install_log_stream_handler() -> None:
    global _installed
    if _installed:
        return

    root_logger = logging.getLogger()
    root_logger.addHandler(_handler)
    _installed = True


def get_log_entries() -> list[dict[str, Any]]:
    return _handler.get_entries()
