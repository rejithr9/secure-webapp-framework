"""Database engine, session factory and shared column types."""

from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import DateTime, Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from swf.config import get_settings


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every backend (SQLite drops the zone)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to UTCDateTime")
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def configure(engine: Engine) -> None:
    """Point the app at an engine (used by tests and at start-up)."""
    global _engine, _session_factory
    _engine = engine
    _session_factory = sessionmaker(bind=engine, expire_on_commit=False)


def get_engine() -> Engine:
    if _engine is None:
        configure(create_engine(get_settings().database_url, pool_pre_ping=True))
    if _engine is None:  # pragma: no cover - configure() always sets it
        raise RuntimeError("database engine not configured")
    return _engine


def session_factory() -> sessionmaker[Session]:
    get_engine()
    if _session_factory is None:  # pragma: no cover
        raise RuntimeError("session factory not configured")
    return _session_factory


def get_db() -> Iterator[Session]:
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()
