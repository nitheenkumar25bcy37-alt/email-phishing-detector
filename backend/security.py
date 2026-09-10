from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from threading import Lock


class RequestRateLimiter:
    """Small process-local limiter; use a gateway/distributed limiter in production."""

    def __init__(self, limit: int = 60, window_seconds: int = 60):
        self.limit = max(1, limit)
        self.window_seconds = max(1, window_seconds)
        self._events = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


def validate_identifier(value: str, name: str = "identifier") -> str:
    if not ID_PATTERN.fullmatch(value or ""):
        raise ValueError(f"Invalid {name}")
    return value


def mask_email_address(value: str) -> str:
    value = str(value or "")
    if "@" not in value:
        return value
    local, domain = value.split("@", 1)
    return f"{(local[:1] or '*')}***@{domain}"