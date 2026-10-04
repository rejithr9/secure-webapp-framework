"""Fixed-window rate limiting per client address.

In-memory, so limits are per process. The framework is designed to run as a single
back-end process (one uvicorn worker), which is plenty for small multi-user apps.
The per-account lockout in `swf.services.signin` works across processes regardless.
"""

import threading
from dataclasses import dataclass

from fastapi import Request

from swf import clock
from swf.config import get_settings
from swf.errors import AppError


@dataclass(frozen=True)
class Limit:
    max_hits: int
    window_seconds: int


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str, int, int], int] = {}
        self._lock = threading.Lock()

    def hit(self, bucket: str, key: str, limits: list[Limit]) -> int | None:
        """Record one hit. Returns None if allowed, else the seconds until the caller may retry."""
        now = int(clock.utcnow().timestamp())
        with self._lock:
            for limit in limits:
                window = now // limit.window_seconds
                if self._hits.get((bucket, key, limit.window_seconds, window), 0) >= limit.max_hits:
                    return (window + 1) * limit.window_seconds - now
            for limit in limits:
                slot = (bucket, key, limit.window_seconds, now // limit.window_seconds)
                self._hits[slot] = self._hits.get(slot, 0) + 1
            if len(self._hits) > 50_000:
                self._prune(now)
        return None

    def _prune(self, now: int) -> None:
        for slot in [s for s in self._hits if (s[3] + 1) * s[2] < now]:
            del self._hits[slot]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_key(request: Request) -> str:
    # uvicorn --proxy-headers puts the real client address here when behind Caddy.
    return request.client.host if request.client else "unknown"


def too_many(retry_after: int) -> AppError:
    minutes = max(1, round(retry_after / 60))
    return AppError(
        429,
        "too_many_requests",
        f"Too many attempts from your network. Please wait about {minutes} minute(s) and try again.",
        headers={"Retry-After": str(retry_after)},
    )


def auth_rate_limit(request: Request) -> None:
    """FastAPI dependency for sign-in endpoints."""
    settings = get_settings()
    retry = limiter.hit(
        "auth",
        client_key(request),
        [Limit(settings.rate_limit_auth_per_minute, 60), Limit(settings.rate_limit_auth_per_hour, 3600)],
    )
    if retry is not None:
        raise too_many(retry)
