"""2FA recovery codes and passkeys (WebAuthn) as a second factor."""

from sqlalchemy import select

from swf.models import Passkey, RecoveryCode, User
from swf.testing import SoftAuthenticator
from tests.conftest import create_account, new_client, next_code, sign_in

# ---- Recovery codes ----


def test_recovery_codes_are_shown_once_and_stored_hashed(alice, db) -> None:
    codes = alice.recovery_codes
    assert codes and len(codes) == 10 and len(set(codes)) == 10
    stored = db.scalars(select(RecoveryCode)).all()
    assert len(stored) == 10
    for row in stored:
        assert all(code not in row.code_hash for code in codes)
    assert alice.client.get("/api/me/recovery-codes").json() == {"enabled": True, "remaining": 10}


def test_sign_in_with_recovery_code_is_single_use(alice, clock) -> None:
    c = new_client()
    c.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    assert c.get("/api/auth/session").json()["recovery_available"] is True
    code = alice.recovery_codes[0]
    r = c.post("/api/auth/recovery", json={"code": code.lower().replace("-", " ")})  # forgiving format
    assert r.status_code == 200 and r.json() == {"next": "dashboard", "recovery_codes_left": 9}

    c2 = new_client()
    c2.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    r = c2.post("/api/auth/recovery", json={"code": code})
    assert r.status_code == 401 and r.json()["code"] == "wrong_recovery_code"

    types = [i["type"] for i in c.get("/api/me/audit").json()["items"]]
    assert "recovery_code_used" in types


def test_wrong_recovery_codes_count_towards_lockout(alice) -> None:
    c = new_client()
    for _ in range(4):
        c.post("/api/auth/login", json={"username": "alice", "password": alice.password})
        assert c.post("/api/auth/recovery", json={"code": "AAAAA-AAAAA"}).status_code == 401
    c.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    r = c.post("/api/auth/recovery", json={"code": "AAAAA-AAAAA"})
    assert r.json()["code"] == "sign_in_failed"
    r = c.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    assert r.status_code == 401  # locked


def test_regenerating_codes_needs_reauth_and_replaces_old(alice, clock) -> None:
    c = alice.client
    r = c.post(
        "/api/me/recovery-codes", json={"password": "wrong password!", "totp_code": next_code(alice.secret, clock)}
    )
    assert r.status_code == 400
    r = c.post("/api/me/recovery-codes", json={"password": alice.password, "totp_code": next_code(alice.secret, clock)})
    new_codes = r.json()["codes"]
    assert len(new_codes) == 10 and not set(new_codes) & set(alice.recovery_codes)

    fresh = new_client()
    fresh.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    assert fresh.post("/api/auth/recovery", json={"code": alice.recovery_codes[1]}).status_code == 401
    assert fresh.post("/api/auth/recovery", json={"code": new_codes[0]}).status_code == 200


def test_recovery_not_possible_before_password(client) -> None:
    r = client.post("/api/auth/recovery", json={"code": "AAAAA-AAAAA"})
    assert r.status_code == 401 and r.json()["code"] == "not_signed_in"


# ---- Passkeys ----


def _add_passkey(person, clock, authenticator: SoftAuthenticator, name: str = "Laptop"):  # type: ignore[no-untyped-def]
    c = person.client
    r = c.post(
        "/api/me/passkeys/options", json={"password": person.password, "totp_code": next_code(person.secret, clock)}
    )
    assert r.status_code == 200, r.text
    options = r.json()
    assert options["rp"]["id"] == "testserver"
    return c.post("/api/me/passkeys", json={"credential": authenticator.register(options), "name": name})


def test_add_passkey_and_sign_in_with_it(alice, clock, db) -> None:
    device = SoftAuthenticator()
    r = _add_passkey(alice, clock, device)
    assert r.status_code == 201 and r.json()["name"] == "Laptop"
    listed = alice.client.get("/api/me/passkeys").json()
    assert listed["enabled"] and [p["name"] for p in listed["items"]] == ["Laptop"]

    c = new_client()
    c.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    assert c.get("/api/auth/session").json()["passkey_available"] is True
    options = c.post("/api/auth/passkey/options").json()
    r = c.post("/api/auth/passkey/verify", json={"credential": device.authenticate(options)})
    assert r.status_code == 200 and r.json()["next"] == "dashboard"
    assert c.get("/api/me").status_code == 200

    stored = db.scalar(select(Passkey))
    db.refresh(stored)
    assert stored.sign_count == 1 and stored.last_used_at is not None
    summaries = [i["summary"] for i in c.get("/api/me/audit").json()["items"] if i["type"] == "sign_in_success"]
    assert any("passkey" in s for s in summaries)


def test_adding_passkey_needs_reauth(alice, clock) -> None:
    r = alice.client.post("/api/me/passkeys/options", json={"password": "wrong password!", "totp_code": "000000"})
    assert r.status_code == 400
    r = alice.client.post(
        "/api/me/passkeys", json={"credential": SoftAuthenticator().register({"challenge": "x"}), "name": "x"}
    )
    assert r.status_code == 400 and r.json()["code"] == "passkey_not_added"  # no challenge was issued


def test_passkey_challenge_is_single_use_and_expires(alice, clock) -> None:
    device = SoftAuthenticator()
    _add_passkey(alice, clock, device)

    c = new_client()
    c.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    options = c.post("/api/auth/passkey/options").json()
    assertion = device.authenticate(options)
    clock.advance(minutes=6)
    r = c.post("/api/auth/passkey/verify", json={"credential": assertion})
    assert r.status_code == 401 and r.json()["code"] == "passkey_failed"
    # Replaying the same (now used-up) challenge fails too.
    assert c.post("/api/auth/passkey/verify", json={"credential": assertion}).status_code == 401


def test_passkey_from_wrong_origin_or_wrong_key_is_refused(alice, clock) -> None:
    device = SoftAuthenticator()
    _add_passkey(alice, clock, device)
    c = new_client()
    c.post("/api/auth/login", json={"username": "alice", "password": alice.password})

    options = c.post("/api/auth/passkey/options").json()
    phished = device.authenticate(options, origin="https://evil.example")
    assert c.post("/api/auth/passkey/verify", json={"credential": phished}).status_code == 401

    options = c.post("/api/auth/passkey/options").json()
    impostor = SoftAuthenticator()
    impostor.credential_id = device.credential_id  # same id, different private key
    assert c.post("/api/auth/passkey/verify", json={"credential": impostor.authenticate(options)}).status_code == 401


def test_passkey_registration_from_wrong_origin_is_refused(alice, clock) -> None:
    c = alice.client
    options = c.post(
        "/api/me/passkeys/options", json={"password": alice.password, "totp_code": next_code(alice.secret, clock)}
    ).json()
    credential = SoftAuthenticator().register(options, origin="https://evil.example")
    assert c.post("/api/me/passkeys", json={"credential": credential, "name": "x"}).status_code == 400


def test_remove_passkey(alice, clock) -> None:
    _add_passkey(alice, clock, SoftAuthenticator())
    pk_id = alice.client.get("/api/me/passkeys").json()["items"][0]["id"]
    assert alice.client.delete(f"/api/me/passkeys/{pk_id}").status_code == 204
    assert alice.client.get("/api/me/passkeys").json()["items"] == []
    assert alice.client.delete(f"/api/me/passkeys/{pk_id}").status_code == 404


def test_passkey_options_without_passkeys(client, clock, db) -> None:
    initial = create_account(db, "carol")
    secret = sign_in(client, clock, "carol", initial)
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "carol", "password": initial})
    assert client.get("/api/auth/session").json()["passkey_available"] is False
    assert client.post("/api/auth/passkey/options").status_code == 404
    assert secret


def test_admin_reset_removes_passkeys_and_recovery_codes(admin, alice, clock, db) -> None:
    _add_passkey(alice, clock, SoftAuthenticator())
    alice_id = db.scalar(select(User.id).where(User.username == "alice"))
    admin.client.post(f"/api/admin/users/{alice_id}/reset")
    db.expire_all()
    assert db.scalars(select(Passkey)).all() == []
    assert db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == alice_id)).all() == []
