"""Single source of 'now', so tests can move time forward."""

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)
