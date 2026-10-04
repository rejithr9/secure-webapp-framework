"""Terms gate, key vault endpoints and the user's own audit trail."""

from sqlalchemy import select

from swf.models import UserSecret
from tests.conftest import NEW_PASSWORD, create_account, next_code, sign_in

KEY = "sk-or-v1-abcdefghijklmnopqrstuvwxyz-9876"


def _signed_in_without_terms(client, clock, db):  # type: ignore[no-untyped-def]
    initial = create_account(db, "carol")
    secret = sign_in(client, clock, "carol", initial)
    client.post(
        "/api/auth/password",
        json={"current_password": initial, "new_password": NEW_PASSWORD, "totp_code": next_code(secret, clock)},
    )
    return secret


def test_terms_text_is_public(client) -> None:
    body = client.get("/api/terms").json()
    assert body["version"] == "1"
    assert "private tool" in body["text"]


def test_terms_gate_blocks_user_endpoints(client, clock, db) -> None:
    _signed_in_without_terms(client, clock, db)
    for method, path, kwargs in [
        ("GET", "/api/keys", {}),
        ("PUT", "/api/keys/weather", {"json": {"secret": KEY}}),
        ("DELETE", "/api/keys/weather", {}),
        ("GET", "/api/me/audit", {}),
        ("GET", "/api/admin/users", {}),
    ]:
        r = client.request(method, path, **kwargs)
        assert r.status_code == 403, path
        assert r.json()["code"] == "terms_not_accepted", path
    # The account page still works, so the user can see what is needed.
    assert client.get("/api/me").json()["next"] == "accept_terms"


def test_accepting_old_terms_version_is_refused(client, clock, db) -> None:
    _signed_in_without_terms(client, clock, db)
    r = client.post("/api/me/terms/accept", json={"version": "0"})
    assert r.status_code == 409
    assert client.post("/api/me/terms/accept", json={"version": "1"}).status_code == 200
    assert client.get("/api/keys").status_code == 200


def test_add_list_replace_delete_key(alice, db) -> None:
    c = alice.client
    r = c.put("/api/keys/ai_service", json={"secret": KEY, "label": "Milo"})
    assert r.status_code == 200
    assert r.json() == {"provider": "ai_service", "masked": "••••9876", "replaced": False}

    items = {i["provider"]: i for i in c.get("/api/keys").json()["items"]}
    assert items["ai_service"]["has_key"] is True
    assert items["ai_service"]["masked"] == "••••9876"
    assert items["ai_service"]["label"] == "Milo"
    assert items["maps"]["has_key"] is False and items["maps"]["unlocks"]

    r = c.put("/api/keys/ai_service", json={"secret": "new-key-0000-1111"})
    assert r.json()["replaced"] is True
    assert db.scalars(select(UserSecret)).all().__len__() == 1

    assert c.delete("/api/keys/ai_service").status_code == 204
    assert c.delete("/api/keys/ai_service").status_code == 404


def test_keys_never_returned_in_full_or_stored_in_plain(alice, db) -> None:
    c = alice.client
    put = c.put("/api/keys/maps", json={"secret": KEY})
    listed = c.get("/api/keys")
    audit = c.get("/api/me/audit")
    for response in (put, listed, audit):
        assert KEY not in response.text
        assert KEY[:-4] not in response.text
    row = db.scalar(select(UserSecret))
    assert KEY.encode() not in row.ciphertext
    assert len(row.nonce) == 12


def test_unknown_provider_and_bad_key(alice) -> None:
    assert alice.client.put("/api/keys/madeup", json={"secret": KEY}).status_code == 404
    r = alice.client.put("/api/keys/weather", json={"secret": "has spaces in it"})
    assert r.status_code == 422 and r.json()["code"] == "invalid_key"


def test_key_service_use_updates_last_used(alice, db, clock) -> None:
    from swf.models import User
    from swf.services import keys

    alice.client.put("/api/keys/weather", json={"secret": KEY})
    user = db.scalar(select(User).where(User.username == "alice"))
    assert keys.use(db, user, "weather") == KEY
    item = next(i for i in alice.client.get("/api/keys").json()["items"] if i["provider"] == "weather")
    assert item["last_used_at"] is not None


def test_audit_trail_records_actions(alice, clock) -> None:
    c = alice.client
    c.put("/api/keys/weather", json={"secret": KEY})
    c.put("/api/keys/weather", json={"secret": KEY + "x"})
    c.delete("/api/keys/weather")
    c.post("/api/auth/login", json={"username": "alice", "password": "wrong password!"})
    sign_in(c, clock, "alice", alice.password, alice.secret)

    items = c.get("/api/me/audit").json()["items"]
    types = [i["type"] for i in items]
    for expected in (
        "totp_enabled",
        "sign_in_success",
        "password_changed",
        "terms_accepted",
        "key_added",
        "key_replaced",
        "key_removed",
        "sign_in_failed",
    ):
        assert expected in types, expected
    added = next(i for i in items if i["type"] == "key_added")
    assert added["details"] == {"provider": "weather"}
    assert added["label"] == "Key added"
    ids = [i["id"] for i in items]
    assert ids == sorted(ids, reverse=True)


def test_audit_pagination(alice) -> None:
    c = alice.client
    for _ in range(6):
        c.put("/api/keys/weather", json={"secret": KEY})
    page1 = c.get("/api/me/audit", params={"limit": 3}).json()
    assert len(page1["items"]) == 3 and page1["has_more"]
    page2 = c.get("/api/me/audit", params={"limit": 3, "before_id": page1["items"][-1]["id"]}).json()
    assert page2["items"][0]["id"] < page1["items"][-1]["id"]


def test_audit_details_are_encrypted_at_rest(alice, db) -> None:
    from swf.models import AuditEvent

    alice.client.put("/api/keys/storage", json={"secret": KEY})
    row = db.scalars(select(AuditEvent).where(AuditEvent.event_type == "key_added")).one()
    assert b"storage" not in row.details_enc
