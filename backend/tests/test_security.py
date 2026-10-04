"""HTTP hardening: headers, hosts, body size, cross-site requests, rate limits, injection, errors."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from swf.config import get_settings
from swf.models import AuditEvent, User
from tests.conftest import app, create_account, new_client


def test_api_responses_carry_security_headers(client) -> None:
    r = client.get("/api/health")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert "server" not in r.headers


def test_unknown_host_is_refused(engine) -> None:
    evil = TestClient(app, base_url="https://evil.example")
    assert evil.get("/api/health").status_code == 400


def test_oversized_body_is_refused(client) -> None:
    big = "x" * (get_settings().max_request_bytes + 1)
    r = client.post("/api/auth/login", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.json()["code"] == "request_too_large"


def test_cross_site_requests_are_refused_even_with_token(alice) -> None:
    c = alice.client
    for headers in (
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
    ):
        r = c.put("/api/me/preferences", json={"theme": "dark"}, headers=headers)
        assert r.status_code == 403, headers
        assert r.json()["code"] == "csrf_failed"
    ok = c.put(
        "/api/me/preferences",
        json={"theme": "dark"},
        headers={"Sec-Fetch-Site": "same-origin", "Origin": "https://testserver"},
    )
    assert ok.status_code == 200


def test_sign_in_rate_limit_per_address(client, monkeypatch, db) -> None:
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MINUTE", "3")
    get_settings.cache_clear()
    try:
        create_account(db, "carol")
        codes = [
            client.post("/api/auth/login", json={"username": f"user{i}", "password": "wrong password!"}).status_code
            for i in range(4)
        ]
        assert codes == [401, 401, 401, 429]
        r = client.post("/api/auth/login", json={"username": "x", "password": "y"})
        assert r.json()["code"] == "too_many_requests" and int(r.headers["retry-after"]) > 0
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_rate_limit_window_resets(client, clock, monkeypatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_AUTH_PER_MINUTE", "2")
    get_settings.cache_clear()
    try:
        for _ in range(2):
            client.post("/api/auth/login", json={"username": "x", "password": "y"})
        assert client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code == 429
        clock.advance(seconds=61)
        assert client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code == 401
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_api_rate_limit(client, monkeypatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_API_PER_MINUTE", "5")
    get_settings.cache_clear()
    try:
        statuses = [client.get("/api/health").status_code for _ in range(6)]
        assert statuses[-1] == 429 and statuses[:5] == [200] * 5
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


SQL_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "'; DROP TABLE users; --",
    '" OR ""="',
    "1; SELECT pg_sleep(5)",
    "alice' UNION SELECT password_hash FROM users--",
]


@pytest.mark.parametrize("payload", SQL_PAYLOADS)
def test_sql_injection_in_sign_in_is_harmless(client, db, payload) -> None:
    create_account(db, "carol")
    r = client.post("/api/auth/login", json={"username": payload, "password": payload})
    assert r.status_code == 401 and r.json()["code"] == "sign_in_failed"
    assert db.scalar(select(func.count()).select_from(User)) == 1


@pytest.mark.parametrize("payload", SQL_PAYLOADS)
def test_sql_injection_in_user_input_is_stored_as_plain_text(alice, db, payload) -> None:
    r = alice.client.put("/api/keys/weather", json={"secret": "valid-key-1234", "label": payload})
    assert r.status_code == 200
    items = {i["provider"]: i for i in alice.client.get("/api/keys").json()["items"]}
    assert items["weather"]["label"] == payload.strip()
    assert db.scalar(select(func.count()).select_from(User)) == 1


def test_injection_in_path_and_query_is_rejected_or_harmless(alice) -> None:
    assert alice.client.put("/api/keys/' OR 1=1--", json={"secret": "valid-key-1234"}).status_code == 404
    assert alice.client.get("/api/me/audit", params={"before_id": "1 OR 1=1"}).status_code == 422


def test_unknown_route_returns_plain_json(client) -> None:
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.json()["code"] == "not_found"


def test_server_errors_do_not_leak_details(engine, monkeypatch) -> None:
    from swf.routers import public

    def boom() -> dict:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(public, "get_app_config", boom)
    c = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
    r = c.get("/api/config")
    assert r.status_code == 500
    assert r.json()["code"] == "server_error"
    assert "secret internal detail" not in r.text


def test_public_config_hides_versions(client) -> None:
    body = client.get("/api/config").json()
    assert body["app_name"] == "Test App"
    assert "version" not in str(body).lower().replace("terms_enabled", "")


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="PostgreSQL only")
def test_audit_tables_are_append_only_in_postgres(alice, db) -> None:
    from sqlalchemy.exc import DBAPIError

    with pytest.raises(DBAPIError):
        db.execute(text("UPDATE audit_events SET event_type = 'forged'"))
    db.rollback()
    with pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM admin_events"))
    db.rollback()
    assert db.scalar(select(func.count()).select_from(AuditEvent)) > 0


def test_new_client_helper_is_same_origin(engine) -> None:
    assert str(new_client().base_url) == "https://testserver"
