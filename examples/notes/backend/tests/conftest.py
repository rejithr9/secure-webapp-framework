"""How an app tests itself with swf.testing."""

import os

from swf.testing import setup_test_env

setup_test_env()

import pytest  # noqa: E402
from swf import db as swf_db  # noqa: E402
from swf.security.ratelimit import limiter  # noqa: E402
from swf.testing import FakeClock, make_sqlite_engine, onboard, prepare_postgres, truncate_postgres  # noqa: E402

from notes_app.main import MIGRATIONS, MODEL_MODULES, app  # noqa: E402

PG_URL = os.environ.get("TEST_DATABASE_URL")
_pg = None


@pytest.fixture
def clock(monkeypatch):  # type: ignore[no-untyped-def]
    fake = FakeClock()
    monkeypatch.setattr("swf.clock.utcnow", fake)
    return fake


@pytest.fixture
def db(clock):  # type: ignore[no-untyped-def]
    global _pg
    limiter.reset()
    if PG_URL:
        if _pg is None:
            _pg = prepare_postgres(PG_URL, str(MIGRATIONS), MODEL_MODULES)
        truncate_postgres(_pg)
        swf_db.configure(_pg)
    else:
        make_sqlite_engine()
    with swf_db.session_factory()() as session:
        yield session


@pytest.fixture
def alice(db, clock):  # type: ignore[no-untyped-def]
    return onboard(app, db, clock, "alice")


@pytest.fixture
def bob(db, clock):  # type: ignore[no-untyped-def]
    return onboard(app, db, clock, "bob")
