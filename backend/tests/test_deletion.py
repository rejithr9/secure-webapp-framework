"""Self-deletion and the retention purge."""

from sqlalchemy import func, select

from swf import retention
from swf.models import AdminEvent, AuditEvent, User, UserSecret, UserSession
from swf.security.sessions import SESSION_COOKIE
from tests.conftest import new_client, next_code, onboard


def _count(db, model, **where) -> int:  # type: ignore[no-untyped-def]
    stmt = select(func.count()).select_from(model)
    for column, value in where.items():
        stmt = stmt.where(getattr(model, column) == value)
    return db.scalar(stmt)


def test_self_deletion_removes_everything(alice, db, clock) -> None:
    alice.client.put("/api/keys/weather", json={"secret": "alice-key-12345678"})
    user_id = db.scalar(select(User.id).where(User.username == "alice"))
    token = alice.client.cookies.get(SESSION_COOKIE)

    r = alice.client.request(
        "DELETE", "/api/me", json={"password": alice.password, "totp_code": next_code(alice.secret, clock)}
    )
    assert r.status_code == 204

    db.expire_all()
    assert db.get(User, user_id) is None
    for model in (UserSession, UserSecret, AuditEvent):
        assert _count(db, model, user_id=user_id) == 0, model.__name__
    event = db.scalar(select(AdminEvent).where(AdminEvent.action == "account_self_deleted"))
    assert event.target_username == "alice"

    other = new_client()
    other.cookies.set(SESSION_COOKIE, token)
    assert other.get("/api/me").status_code == 401
    r = other.post("/api/auth/login", json={"username": "alice", "password": alice.password})
    assert r.status_code == 401


def test_self_deletion_needs_password_and_code(alice, db, clock) -> None:
    c = alice.client
    r = c.request(
        "DELETE", "/api/me", json={"password": "wrong password!", "totp_code": next_code(alice.secret, clock)}
    )
    assert r.status_code == 400
    r = c.request("DELETE", "/api/me", json={"password": alice.password, "totp_code": "000000"})
    assert r.status_code == 401
    assert _count(db, User, username="alice") == 1


def test_only_admin_cannot_delete_self_while_others_exist(admin, alice, clock) -> None:
    r = admin.client.request(
        "DELETE", "/api/me", json={"password": admin.password, "totp_code": next_code(admin.secret, clock)}
    )
    assert r.status_code == 409 and r.json()["code"] == "last_admin"


def test_retention_purge(admin, alice, db, clock) -> None:
    keep = onboard(db, clock, "keeper")
    alice.client.put("/api/keys/weather", json={"secret": "alice-key-12345678"})
    alice_id = next(u["id"] for u in admin.client.get("/api/admin/users").json()["items"] if u["username"] == "alice")
    admin.client.post(f"/api/admin/users/{alice_id}/deactivate")

    clock.advance(days=181)
    assert retention.run_once() == 0
    clock.advance(days=1, seconds=1)
    assert retention.run_once() == 1

    db.expire_all()
    assert _count(db, User, username="alice") == 0
    assert _count(db, UserSecret) == 0
    assert _count(db, User, username="keeper") == 1 and _count(db, User, username="boss") == 1
    assert db.scalar(select(AdminEvent).where(AdminEvent.action == "retention_purge")).target_username == "alice"
    assert keep.username == "keeper"


def test_retention_follows_admin_setting(admin, alice, db, clock) -> None:
    admin.client.put("/api/admin/settings", json={"retention_days": 30})
    alice_id = next(u["id"] for u in admin.client.get("/api/admin/users").json()["items"] if u["username"] == "alice")
    admin.client.post(f"/api/admin/users/{alice_id}/deactivate")
    clock.advance(days=29)
    assert retention.run_once() == 0
    clock.advance(days=2)
    assert retention.run_once() == 1


def test_reactivated_user_is_not_purged(admin, alice, db, clock) -> None:
    alice_id = next(u["id"] for u in admin.client.get("/api/admin/users").json()["items"] if u["username"] == "alice")
    admin.client.post(f"/api/admin/users/{alice_id}/deactivate")
    clock.advance(days=10)
    # Fresh sign-in for the admin, whose session timed out while time moved on.
    from tests.conftest import sign_in

    sign_in(admin.client, clock, admin.username, admin.password, admin.secret)
    admin.client.post(f"/api/admin/users/{alice_id}/reactivate")
    clock.advance(days=200)
    assert retention.run_once() == 0
