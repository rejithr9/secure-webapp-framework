"""Admin area: account management only, and no route that reaches another user's data."""

from sqlalchemy import select

from swf.models import AdminEvent, User, UserSecret
from swf.services import keys
from tests.conftest import app, create_account, new_client, next_code, onboard, sign_in

ALICE_KEY = "alice-private-key-ALICE-7777"

# Every API route must be listed here. A new route makes test_every_route_is_classified fail,
# so whoever adds it has to decide (and test) who may reach it.
PUBLIC_ROUTES = {("GET", "/api/health"), ("GET", "/api/terms"), ("GET", "/api/config")}
AUTH_ROUTES = {
    ("GET", "/api/auth/session"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/auth/totp/setup"),
    ("POST", "/api/auth/totp/enable"),
    ("POST", "/api/auth/totp/verify"),
    ("POST", "/api/auth/recovery"),
    ("POST", "/api/auth/passkey/options"),
    ("POST", "/api/auth/passkey/verify"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/password"),
}
USER_DATA_ROUTES = {
    ("GET", "/api/me"),
    ("POST", "/api/me/terms/accept"),
    ("PUT", "/api/me/preferences"),
    ("GET", "/api/me/audit"),
    ("DELETE", "/api/me"),
    ("GET", "/api/me/recovery-codes"),
    ("POST", "/api/me/recovery-codes"),
    ("GET", "/api/me/passkeys"),
    ("POST", "/api/me/passkeys/options"),
    ("POST", "/api/me/passkeys"),
    ("DELETE", "/api/me/passkeys/{passkey_id}"),
    ("GET", "/api/keys"),
    ("PUT", "/api/keys/{provider}"),
    ("DELETE", "/api/keys/{provider}"),
    ("GET", "/api/echo"),  # the test app's module route
}
ADMIN_ROUTES = {
    ("GET", "/api/admin/users"),
    ("POST", "/api/admin/users"),
    ("POST", "/api/admin/users/{user_id}/reset"),
    ("POST", "/api/admin/users/{user_id}/deactivate"),
    ("POST", "/api/admin/users/{user_id}/reactivate"),
    ("GET", "/api/admin/settings"),
    ("PUT", "/api/admin/settings"),
    ("GET", "/api/admin/events"),
}
ADMIN_USER_FIELDS = {"id", "username", "role", "status", "created_at", "last_login_at"}

WRONG_REAUTH = {"password": "not the password", "totp_code": "000000"}
BODIES = {
    ("POST", "/api/me/terms/accept"): {"version": "1"},
    ("PUT", "/api/me/preferences"): {"theme": "dark"},
    ("DELETE", "/api/me"): WRONG_REAUTH,
    ("POST", "/api/me/recovery-codes"): WRONG_REAUTH,
    ("POST", "/api/me/passkeys/options"): WRONG_REAUTH,
    ("POST", "/api/me/passkeys"): {"credential": {}, "name": "x"},
    ("PUT", "/api/keys/{provider}"): {"secret": "admin-own-key-1234"},
}


def _routes() -> set[tuple[str, str]]:
    # The OpenAPI schema lists every route, however routers are nested.
    app.openapi_schema = None
    paths = app.openapi()["paths"]
    return {(method.upper(), path) for path, ops in paths.items() for method in ops}


def test_every_route_is_classified() -> None:
    assert _routes() == PUBLIC_ROUTES | AUTH_ROUTES | USER_DATA_ROUTES | ADMIN_ROUTES


def test_wrong_reauth_attempts_by_admin_count_against_admin_only(admin, alice, db) -> None:
    """Failed confirmations above lock the *admin's* counter, never another user's."""
    alice_row = db.scalar(select(User).where(User.username == "alice"))
    assert alice_row.failed_login_count == 0


def test_only_admin_routes_take_a_user_id() -> None:
    for method, path in _routes():
        if "{user_id}" in path:
            assert (method, path) in ADMIN_ROUTES
            assert path.rsplit("/", 1)[-1] in {"reset", "deactivate", "reactivate"}


def test_admin_cannot_reach_another_users_data(admin, alice, db, clock) -> None:
    alice.client.put("/api/keys/weather", json={"secret": ALICE_KEY})
    alice.client.put("/api/me/preferences", json={"theme": "dark"})
    alice_row = db.scalar(select(User).where(User.username == "alice"))
    alice_id = str(alice_row.id)
    alice_audit_before = alice.client.get("/api/me/audit").json()["items"]
    alice_passkey_id = str(alice_row.id)  # any id: the admin must never reach Alice's records

    # Try every user-data route as the admin, pointing at Alice in every way we can.
    sneaky = {"user_id": alice_id, "username": "alice", "id": alice_id}
    for method, path in sorted(USER_DATA_ROUTES):
        url = path.replace("{provider}", "weather").replace("{passkey_id}", alice_passkey_id)
        kwargs = {"params": sneaky}
        if (method, path) in BODIES:
            kwargs["json"] = {**BODIES[(method, path)], **sneaky}
        r = admin.client.request(method, url, **kwargs)
        assert r.status_code < 500, (method, path)
        for marker in ("alice", alice_id, ALICE_KEY[-4:], ALICE_KEY):
            assert marker not in r.text, (method, path, marker)

    # Alice's data is untouched.
    db.expire_all()
    alice_row = db.scalar(select(User).where(User.username == "alice"))
    assert alice_row is not None and alice_row.theme == "dark"
    row = db.scalar(select(UserSecret).where(UserSecret.user_id == alice_row.id, UserSecret.provider == "weather"))
    assert keys.reveal(alice_row, row) == ALICE_KEY
    assert alice.client.get("/api/me/audit").json()["items"] == alice_audit_before


def test_admin_routes_never_expose_user_data(admin, alice, db) -> None:
    alice.client.put("/api/keys/weather", json={"secret": ALICE_KEY})
    users = admin.client.get("/api/admin/users").json()["items"]
    assert all(set(u) == ADMIN_USER_FIELDS for u in users)
    for path in ("/api/admin/users", "/api/admin/events", "/api/admin/settings"):
        text = admin.client.get(path).text
        assert ALICE_KEY[-4:] not in text and "theme" not in text and "totp" not in text


def test_non_admin_is_refused_everywhere(alice, admin) -> None:
    some_id = admin.client.get("/api/admin/users").json()["items"][0]["id"]
    for method, path in sorted(ADMIN_ROUTES):
        url = path.replace("{user_id}", some_id)
        body = {"username": "newbie"} if path == "/api/admin/users" else {"retention_days": 30}
        r = alice.client.request(method, url, json=body if method != "GET" else None)
        assert r.status_code == 403, (method, path)
        assert r.json()["code"] == "admin_only"


def test_create_user_and_first_sign_in(admin, clock) -> None:
    r = admin.client.post("/api/admin/users", json={"username": "Dave", "role": "user"})
    assert r.status_code == 201
    body = r.json()
    assert set(body["user"]) == ADMIN_USER_FIELDS
    assert body["user"]["username"] == "dave" and body["user"]["status"] == "setup_pending"
    dave = new_client()
    sign_in(dave, clock, "dave", body["initial_password"])
    assert dave.get("/api/me").json()["next"] == "change_password"


def test_create_user_validation(admin) -> None:
    assert admin.client.post("/api/admin/users", json={"username": "x"}).json()["code"] == "invalid_username"
    admin.client.post("/api/admin/users", json={"username": "dave"})
    assert admin.client.post("/api/admin/users", json={"username": "DAVE"}).json()["code"] == "username_taken"


def test_user_limit_is_ten(admin) -> None:
    for i in range(9):
        assert admin.client.post("/api/admin/users", json={"username": f"friend{i}"}).status_code == 201
    r = admin.client.post("/api/admin/users", json={"username": "one-too-many"})
    assert r.status_code == 409 and r.json()["code"] == "user_limit_reached"


def test_reset_forces_new_password_and_2fa(admin, alice, clock) -> None:
    alice_id = next(u["id"] for u in admin.client.get("/api/admin/users").json()["items"] if u["username"] == "alice")
    r = admin.client.post(f"/api/admin/users/{alice_id}/reset")
    initial = r.json()["initial_password"]
    assert alice.client.get("/api/me").status_code == 401  # signed out everywhere

    fresh = new_client()
    assert fresh.post("/api/auth/login", json={"username": "alice", "password": alice.password}).status_code == 401
    assert fresh.post("/api/auth/login", json={"username": "alice", "password": initial}).json()["next"] == "totp_setup"
    new_secret = fresh.get("/api/auth/totp/setup").json()["secret"]
    assert new_secret != alice.secret
    assert fresh.post("/api/auth/totp/enable", json={"code": next_code(new_secret, clock)}).status_code == 200


def test_reset_clears_lockout(admin, db, clock) -> None:
    create_account(db, "eve")
    c = new_client()
    for _ in range(5):
        c.post("/api/auth/login", json={"username": "eve", "password": "wrong password!"})
    eve = next(u for u in admin.client.get("/api/admin/users").json()["items"] if u["username"] == "eve")
    assert eve["status"] == "locked"
    initial = admin.client.post(f"/api/admin/users/{eve['id']}/reset").json()["initial_password"]
    assert c.post("/api/auth/login", json={"username": "eve", "password": initial}).status_code == 200


def test_deactivate_and_reactivate(admin, alice, clock) -> None:
    alice_id = next(u["id"] for u in admin.client.get("/api/admin/users").json()["items"] if u["username"] == "alice")
    r = admin.client.post(f"/api/admin/users/{alice_id}/deactivate")
    assert r.json()["user"]["status"] == "deactivated"
    assert alice.client.get("/api/me").status_code == 401
    c = new_client()
    assert c.post("/api/auth/login", json={"username": "alice", "password": alice.password}).status_code == 401

    admin.client.post(f"/api/admin/users/{alice_id}/reactivate")
    sign_in(c, clock, "alice", alice.password, alice.secret)
    assert c.get("/api/keys").status_code == 200


def test_admin_cannot_reset_or_deactivate_self(admin) -> None:
    me = admin.client.get("/api/admin/users").json()["items"][0]
    assert admin.client.post(f"/api/admin/users/{me['id']}/reset").status_code == 409
    assert admin.client.post(f"/api/admin/users/{me['id']}/deactivate").status_code == 409


def test_unknown_user_id(admin) -> None:
    r = admin.client.post("/api/admin/users/00000000-0000-0000-0000-000000000000/reset")
    assert r.status_code == 404


def test_retention_setting(admin) -> None:
    assert admin.client.get("/api/admin/settings").json()["retention_days"] == 182
    assert admin.client.put("/api/admin/settings", json={"retention_days": 30}).json()["retention_days"] == 30
    assert admin.client.put("/api/admin/settings", json={"retention_days": 0}).status_code == 422
    assert admin.client.put("/api/admin/settings", json={"retention_days": 183}).status_code == 422
    assert admin.client.get("/api/admin/settings").json()["retention_days"] == 30


def test_admin_actions_are_logged_without_secrets(admin, db) -> None:
    r = admin.client.post("/api/admin/users", json={"username": "dave"})
    initial = r.json()["initial_password"]
    admin.client.put("/api/admin/settings", json={"retention_days": 60})
    events = admin.client.get("/api/admin/events").json()["items"]
    actions = [e["action"] for e in events]
    assert "user_created" in actions and "settings_changed" in actions
    assert initial not in admin.client.get("/api/admin/events").text
    assert all(e["actor"] == "boss" for e in events)
    assert db.scalars(select(AdminEvent)).all()  # stored in the separate admin log


def test_admin_is_also_a_normal_user(admin) -> None:
    assert admin.client.put("/api/keys/weather", json={"secret": "admin-own-key-1234"}).status_code == 200
    assert admin.client.get("/api/me/audit").status_code == 200


def test_second_admin(admin, db, clock) -> None:
    second = onboard(db, clock, "deputy", role="admin")
    assert second.client.get("/api/admin/users").status_code == 200
