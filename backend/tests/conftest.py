"""Framework test fixtures: a generic test app, SQLite (or PostgreSQL via TEST_DATABASE_URL)."""

import os

from swf.testing import setup_test_env

setup_test_env()

import pytest  # noqa: E402
from fastapi import APIRouter, FastAPI  # noqa: E402

from swf import AppConfig, Module, RetentionPolicy, SecretProvider, TermsConfig, create_app  # noqa: E402
from swf import db as swf_db  # noqa: E402
from swf.deps import ReadyUser  # noqa: E402
from swf.security.ratelimit import limiter  # noqa: E402
from swf.testing import (  # noqa: E402
    NEW_PASSWORD,
    ApiClient,
    FakeClock,
    Person,
    create_account,
    make_sqlite_engine,
    next_code,
    prepare_postgres,
    truncate_postgres,
)
from swf.testing import new_client as _new_client  # noqa: E402
from swf.testing import onboard as _onboard  # noqa: E402
from swf.testing import sign_in as _sign_in  # noqa: E402

__all__ = ["NEW_PASSWORD", "create_account", "next_code"]

TERMS_TEXT = """# Terms of use

1. **This is a private tool.** It is not a public service.

2. **Your decisions are your own.** Nobody is responsible for them but you.
"""

echo = APIRouter(prefix="/api/echo", tags=["echo"])


@echo.get("")
def whoami(user: ReadyUser) -> dict:
    return {"username": user.username}


def make_config(**overrides) -> AppConfig:  # type: ignore[no-untyped-def]
    values = dict(
        name="Test App",
        max_users=10,
        terms=TermsConfig("1", TERMS_TEXT),
        secret_providers=[
            SecretProvider("ai_service", "AI Service", "Lets you use the assistant.", "https://example.com/ai"),
            SecretProvider("maps", "Maps", "Shows maps.", "https://example.com/maps"),
            SecretProvider("weather", "Weather", "Shows the weather.", "https://example.com/weather"),
            SecretProvider("storage", "Storage", "Stores files.", "https://example.com/storage"),
        ],
        retention=RetentionPolicy(max_total_days=182, backup_days=0),
        modules=[Module(name="echo", routers=[echo], audit_labels={"echo_called": "Echo called"})],
    )
    values.update(overrides)
    return AppConfig(**values)


app: FastAPI = create_app(make_config())
PG_URL = os.environ.get("TEST_DATABASE_URL")
_pg_engine = None


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr("swf.clock.utcnow", fake)
    return fake


@pytest.fixture
def engine():  # type: ignore[no-untyped-def]
    global _pg_engine
    limiter.reset()
    if PG_URL:
        if _pg_engine is None:
            _pg_engine = prepare_postgres(PG_URL)
        truncate_postgres(_pg_engine)
        swf_db.configure(_pg_engine)
        yield _pg_engine
        return
    eng = make_sqlite_engine()
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):  # type: ignore[no-untyped-def]
    with swf_db.session_factory()() as session:
        yield session


@pytest.fixture(autouse=True)
def _default_config():  # type: ignore[no-untyped-def]
    """Each test starts from the default test config (some tests swap it)."""
    from swf.appconfig import set_app_config

    set_app_config(make_config())
    yield


def new_client() -> ApiClient:
    return _new_client(app)


def sign_in(client: ApiClient, clock: FakeClock, username: str, password: str, secret: str | None = None) -> str:
    return _sign_in(client, clock, username, password, secret).secret


def onboard(db, clock: FakeClock, username: str, role: str = "user") -> Person:  # type: ignore[no-untyped-def]
    return _onboard(app, db, clock, username, role)


@pytest.fixture
def client(engine, clock) -> ApiClient:  # type: ignore[no-untyped-def]
    return new_client()


@pytest.fixture
def alice(engine, clock, db) -> Person:  # type: ignore[no-untyped-def]
    return onboard(db, clock, "alice")


@pytest.fixture
def admin(engine, clock, db) -> Person:  # type: ignore[no-untyped-def]
    return onboard(db, clock, "boss", role="admin")
