"""Test helpers for the framework and for apps built on it.

Typical app `conftest.py`:

    from swf.testing import setup_test_env
    setup_test_env()                      # before importing the app

    from swf.testing import *             # noqa: F403  (fixtures helpers below)
    from myapp.main import app

Requires the `testing` extra: pip install "secure-webapp-framework[testing]".
"""

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import cbor2
import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

NEW_PASSWORD = "correct horse battery staple"
TEST_ORIGIN = "https://testserver"
TEST_RP_ID = "testserver"


def setup_test_env(**overrides: str) -> None:
    """Set safe test settings. Call before the app (and swf.config) is first used."""
    env = {
        "MASTER_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "ENVIRONMENT": "test",
        "RETENTION_JOB_ENABLED": "false",
        "DATABASE_URL": "sqlite://",
        "ALLOWED_HOSTS": "testserver",
        "WEBAUTHN_RP_ID": TEST_RP_ID,
        "WEBAUTHN_ORIGIN": TEST_ORIGIN,
        "RATE_LIMIT_AUTH_PER_MINUTE": "1000",
        "RATE_LIMIT_AUTH_PER_HOUR": "10000",
        "RATE_LIMIT_API_PER_MINUTE": "100000",
    }
    env.update(overrides)
    os.environ.update(env)
    from swf.config import get_settings

    get_settings.cache_clear()


class FakeClock:
    """Replaces swf.clock.utcnow so tests can move time forward."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


# ---- Database ----


def make_sqlite_engine() -> Engine:
    """A fresh in-memory SQLite database with foreign keys on and all tables created."""
    from swf import db
    from swf.db import Base

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_conn, _):  # type: ignore[no-untyped-def]
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    db.configure(engine)
    return engine


def prepare_postgres(url: str, app_versions: str | None = None, model_modules: list[str] | None = None) -> Engine:
    """Reset a PostgreSQL test database and apply all migrations (once per test session)."""
    from swf import db, migrate

    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    migrate.upgrade(url, app_versions, model_modules)
    db.configure(engine)
    return engine


def truncate_postgres(engine: Engine) -> None:
    """Empty every table between tests (TRUNCATE bypasses the append-only row triggers)."""
    from swf.db import Base

    names = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))  # noqa: S608 - table names from metadata


# ---- HTTP client ----


class ApiClient(TestClient):
    """Behaves like the front end: same-origin requests that echo the CSRF cookie in a header."""

    def request(self, method, url, **kwargs):  # type: ignore[no-untyped-def, override]
        from swf.security.sessions import CSRF_COOKIE, CSRF_HEADER

        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            if CSRF_COOKIE not in self.cookies:
                super().request("GET", "/api/auth/session")
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault(CSRF_HEADER, self.cookies.get(CSRF_COOKIE))
            kwargs["headers"] = headers
        return super().request(method, url, **kwargs)


def new_client(app: FastAPI) -> ApiClient:
    return ApiClient(app, base_url=TEST_ORIGIN)


# ---- Sign-in helpers ----


def next_code(secret: str, clock: FakeClock) -> str:
    """Move to the next 30-second window and return its code (each code is single-use)."""
    clock.advance(seconds=30)
    return pyotp.TOTP(secret).at(clock.now)


def create_account(db: Session, username: str, role: str = "user") -> str:
    from swf.services import users

    _, initial_password = users.create_user(db, username, role)
    db.commit()
    return initial_password


@dataclass
class SignIn:
    secret: str
    recovery_codes: list[str] | None


def sign_in(client: ApiClient, clock: FakeClock, username: str, password: str, secret: str | None = None) -> SignIn:
    """Password + authenticator step. Enrols TOTP on first sign-in."""
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    codes = None
    if r.json()["next"] == "totp_setup":
        secret = client.get("/api/auth/totp/setup").json()["secret"]
        r = client.post("/api/auth/totp/enable", json={"code": next_code(secret, clock)})
        codes = r.json().get("recovery_codes")
    else:
        assert secret is not None
        r = client.post("/api/auth/totp/verify", json={"code": next_code(secret, clock)})
    assert r.status_code == 200, r.text
    assert secret is not None
    return SignIn(secret, codes)


@dataclass
class Person:
    username: str
    password: str
    secret: str
    client: ApiClient
    recovery_codes: list[str] | None = None


def onboard(app: FastAPI, db: Session, clock: FakeClock, username: str, role: str = "user") -> Person:
    """Create an account and take it all the way to a ready session."""
    client = new_client(app)
    initial = create_account(db, username, role)
    result = sign_in(client, clock, username, initial)
    r = client.post(
        "/api/auth/password",
        json={"current_password": initial, "new_password": NEW_PASSWORD, "totp_code": next_code(result.secret, clock)},
    )
    assert r.status_code == 200, r.text
    terms = client.get("/api/terms")
    if terms.status_code == 200:
        r = client.post("/api/me/terms/accept", json={"version": terms.json()["version"]})
        assert r.status_code == 200, r.text
    assert client.get("/api/me").json()["next"] == "dashboard"
    return Person(username, NEW_PASSWORD, result.secret, client, result.recovery_codes)


# ---- Passkeys ----


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    """A software WebAuthn authenticator (ES256, 'none' attestation) for tests."""

    def __init__(self, rp_id: str = TEST_RP_ID, origin: str = TEST_ORIGIN) -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.sign_count = 0

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        payload = {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        return json.dumps(payload).encode()

    def register(self, options: dict[str, Any], origin: str | None = None) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        cose_key = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        attested = bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + cbor2.dumps(cose_key)
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + struct.pack(">I", 0) + attested
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64url(self.credential_id),
            "rawId": _b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url(self._client_data("webauthn.create", options["challenge"], origin)),
                "attestationObject": _b64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def authenticate(self, options: dict[str, Any], origin: str | None = None) -> dict[str, Any]:
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.sign_count)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": _b64url(self.credential_id),
            "rawId": _b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url(client_data),
                "authenticatorData": _b64url(auth_data),
                "signature": _b64url(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
