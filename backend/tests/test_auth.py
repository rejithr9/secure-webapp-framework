"""Sign-in, 2FA, lockout, sessions and CSRF."""

import base64

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from swf.models import User, UserSession
from swf.security.sessions import SESSION_COOKIE, hash_token
from tests.conftest import NEW_PASSWORD, app, create_account, new_client, next_code, sign_in


def test_health(client) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}


def test_first_sign_in_flow(client, clock, db) -> None:
    initial = create_account(db, "carol")
    assert client.get("/api/auth/session").json() == {"stage": "signed_out", "user": None}

    r = client.post("/api/auth/login", json={"username": "Carol", "password": initial})
    assert r.json() == {"next": "totp_setup"}

    setup = client.get("/api/auth/totp/setup").json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    assert setup["qr_svg"].startswith("data:image/svg+xml;base64,")
    svg = base64.b64decode(setup["qr_svg"].split(",", 1)[1]).decode()
    assert svg.startswith("<svg") and "xmlns='http://www.w3.org/2000/svg'" in svg  # renders as <img>
    # Reloading the setup page shows the same secret, so a scanned code keeps working.
    assert client.get("/api/auth/totp/setup").json()["secret"] == setup["secret"]

    r = client.post("/api/auth/totp/enable", json={"code": next_code(setup["secret"], clock)})
    assert r.json()["next"] == "change_password"
    assert len(r.json()["recovery_codes"]) == 10
    state = client.get("/api/auth/session").json()
    assert state["stage"] == "full" and state["user"]["username"] == "carol"

    r = client.post(
        "/api/auth/password",
        json={
            "current_password": initial,
            "new_password": NEW_PASSWORD,
            "totp_code": next_code(setup["secret"], clock),
        },
    )
    assert r.json() == {"next": "accept_terms"}
    r = client.post("/api/me/terms/accept", json={"version": "1"})
    assert r.json()["next"] == "dashboard"

    # Second sign-in asks for the code, not for setup.
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "carol", "password": NEW_PASSWORD})
    assert r.json() == {"next": "totp_verify"}
    r = client.post("/api/auth/totp/verify", json={"code": next_code(setup["secret"], clock)})
    assert r.json() == {"next": "dashboard"}


def test_two_factor_cannot_be_skipped(client, clock, db) -> None:
    initial = create_account(db, "carol")
    client.post("/api/auth/login", json={"username": "carol", "password": initial})
    for path in ("/api/me", "/api/keys", "/api/me/audit"):
        r = client.get(path)
        assert r.status_code == 401 and r.json()["code"] == "second_step_required"


def test_totp_setup_only_during_setup(alice) -> None:
    r = alice.client.get("/api/auth/totp/setup")  # a full session can't re-read or replace the secret
    assert r.status_code == 409 and "secret" not in r.json()


def test_wrong_password_and_unknown_user_look_the_same(client, db) -> None:
    create_account(db, "carol")
    a = client.post("/api/auth/login", json={"username": "carol", "password": "wrong password!"})
    b = client.post("/api/auth/login", json={"username": "nobody", "password": "wrong password!"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()
    assert a.json()["code"] == "sign_in_failed"


def test_lockout_after_wrong_passwords(client, clock, db) -> None:
    initial = create_account(db, "carol")
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "carol", "password": "wrong password!"})
    # Even the right password is refused while locked, with the same generic message.
    r = client.post("/api/auth/login", json={"username": "carol", "password": initial})
    assert r.status_code == 401 and r.json()["code"] == "sign_in_failed"

    clock.advance(minutes=15, seconds=1)
    r = client.post("/api/auth/login", json={"username": "carol", "password": initial})
    assert r.status_code == 200


def test_lockout_after_wrong_codes_and_password_does_not_reset_counter(client, clock, db) -> None:
    initial = create_account(db, "carol")
    secret = sign_in(client, clock, "carol", initial)
    client.post("/api/auth/logout")

    # Re-entering the right password between wrong codes must not reset the counter.
    for _ in range(4):
        client.post("/api/auth/login", json={"username": "carol", "password": initial})
        r = client.post("/api/auth/totp/verify", json={"code": "000000"})
        assert r.json()["code"] in ("wrong_code", "sign_in_failed")
    client.post("/api/auth/login", json={"username": "carol", "password": initial})
    r = client.post("/api/auth/totp/verify", json={"code": "000000"})
    assert r.json()["code"] == "sign_in_failed"  # now locked, pending session ended

    r = client.post("/api/auth/login", json={"username": "carol", "password": initial})
    assert r.status_code == 401
    clock.advance(minutes=16)
    sign_in(client, clock, "carol", initial, secret)


def test_successful_sign_in_resets_failures(client, clock, db) -> None:
    initial = create_account(db, "carol")
    secret = sign_in(client, clock, "carol", initial)
    for _ in range(4):
        client.post("/api/auth/login", json={"username": "carol", "password": "wrong password!"})
    sign_in(client, clock, "carol", initial, secret)
    db.expire_all()
    assert db.scalar(select(User).where(User.username == "carol")).failed_login_count == 0


def test_totp_code_cannot_be_replayed(client, clock, db) -> None:
    initial = create_account(db, "carol")
    secret = sign_in(client, clock, "carol", initial)
    client.post("/api/auth/logout")
    code = pyotp.TOTP(secret).at(clock.now)  # the code that was just used to enable 2FA
    client.post("/api/auth/login", json={"username": "carol", "password": initial})
    r = client.post("/api/auth/totp/verify", json={"code": code})
    assert r.status_code == 401 and r.json()["code"] == "wrong_code"


def test_session_cookie_flags_and_hashed_storage(client, clock, db) -> None:
    initial = create_account(db, "carol")
    r = client.post("/api/auth/login", json={"username": "carol", "password": initial})
    header = next(h for h in r.headers.get_list("set-cookie") if h.startswith(SESSION_COOKIE + "="))
    lowered = header.lower()
    assert "httponly" in lowered and "secure" in lowered and "samesite=strict" in lowered

    token = client.cookies.get(SESSION_COOKIE)
    stored = db.scalars(select(UserSession)).all()
    assert len(stored) == 1
    assert stored[0].token_hash == hash_token(token)
    assert stored[0].token_hash != token


def test_session_token_rotates_after_second_step(client, clock, db) -> None:
    initial = create_account(db, "carol")
    client.post("/api/auth/login", json={"username": "carol", "password": initial})
    pending_token = client.cookies.get(SESSION_COOKIE)
    secret = client.get("/api/auth/totp/setup").json()["secret"]
    client.post("/api/auth/totp/enable", json={"code": next_code(secret, clock)})
    assert client.cookies.get(SESSION_COOKIE) != pending_token
    stolen = new_client()
    stolen.cookies.set(SESSION_COOKIE, pending_token)
    assert stolen.get("/api/me").status_code == 401


def test_idle_timeout(alice, clock) -> None:
    clock.advance(minutes=29)
    assert alice.client.get("/api/me").status_code == 200  # activity refreshes the idle timer
    clock.advance(minutes=29)
    assert alice.client.get("/api/me").status_code == 200
    clock.advance(minutes=31)
    r = alice.client.get("/api/me")
    assert r.status_code == 401 and r.json()["code"] == "not_signed_in"


def test_absolute_timeout(alice, clock) -> None:
    for _ in range(12 * 3):  # stay active every 20 minutes for 12 hours
        clock.advance(minutes=20)
        alice.client.get("/api/me")
    assert alice.client.get("/api/me").status_code == 401


def test_pending_sign_in_expires(client, clock, db) -> None:
    initial = create_account(db, "carol")
    client.post("/api/auth/login", json={"username": "carol", "password": initial})
    clock.advance(minutes=11)
    assert client.get("/api/auth/session").json()["stage"] == "signed_out"


def test_logout_ends_session(alice) -> None:
    token = alice.client.cookies.get(SESSION_COOKIE)
    assert alice.client.post("/api/auth/logout").status_code == 204
    other = new_client()
    other.cookies.set(SESSION_COOKIE, token)
    assert other.get("/api/me").status_code == 401


def test_csrf_rejected_without_or_with_wrong_header(alice, engine) -> None:
    raw = TestClient(app, base_url="https://testserver")
    raw.cookies = alice.client.cookies
    r = raw.post("/api/me/terms/accept", json={"version": "1"})
    assert r.status_code == 403 and r.json()["code"] == "csrf_failed"
    r = raw.post("/api/me/terms/accept", json={"version": "1"}, headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    r = raw.request("DELETE", "/api/keys/weather", headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    # Login itself is protected too (no login CSRF).
    fresh = TestClient(app, base_url="https://testserver")
    r = fresh.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    assert r.status_code == 403


def test_change_password_needs_current_password_and_code(alice, clock) -> None:
    c = alice.client
    r = c.post(
        "/api/auth/password",
        json={
            "current_password": "wrong password!",
            "new_password": "another good password",
            "totp_code": next_code(alice.secret, clock),
        },
    )
    assert r.status_code == 400 and r.json()["code"] == "wrong_password"
    r = c.post(
        "/api/auth/password",
        json={"current_password": alice.password, "new_password": "another good password", "totp_code": "123456"},
    )
    assert r.status_code == 401 and r.json()["code"] == "wrong_code"
    r = c.post(
        "/api/auth/password",
        json={"current_password": alice.password, "new_password": "short", "totp_code": next_code(alice.secret, clock)},
    )
    assert r.status_code == 422 and r.json()["code"] == "weak_password"
    r = c.post(
        "/api/auth/password",
        json={
            "current_password": alice.password,
            "new_password": "another good password",
            "totp_code": next_code(alice.secret, clock),
        },
    )
    assert r.status_code == 200


def test_password_change_signs_out_other_sessions(alice, clock) -> None:
    other = new_client()
    sign_in(other, clock, alice.username, alice.password, alice.secret)
    assert other.get("/api/me").status_code == 200
    alice.client.post(
        "/api/auth/password",
        json={
            "current_password": alice.password,
            "new_password": "another good password",
            "totp_code": next_code(alice.secret, clock),
        },
    )
    assert other.get("/api/me").status_code == 401
    assert alice.client.get("/api/me").status_code == 200


def test_initial_password_must_be_changed(client, clock, db) -> None:
    initial = create_account(db, "carol")
    sign_in(client, clock, "carol", initial)
    r = client.get("/api/keys")
    assert r.status_code == 403 and r.json()["code"] == "password_change_required"
