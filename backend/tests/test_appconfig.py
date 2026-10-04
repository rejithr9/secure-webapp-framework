"""Apps configure the framework: terms, passkeys, recovery codes, retention, modules, user limit."""

import pytest
from fastapi import APIRouter

from swf import AppConfig, Module, RetentionPolicy, SecretProvider, create_app
from swf.appconfig import set_app_config
from tests.conftest import make_config, next_code


def test_module_routes_are_served_and_protected(alice, client) -> None:
    assert alice.client.get("/api/echo").json() == {"username": "alice"}
    assert client.get("/api/echo").status_code == 401


def test_module_audit_labels_are_used(alice, db) -> None:
    from sqlalchemy import select

    from swf.models import User
    from swf.services import audit

    user = db.scalar(select(User).where(User.username == "alice"))
    audit.record(db, user, "echo_called", {"summary": "said hello"})
    db.commit()
    item = alice.client.get("/api/me/audit").json()["items"][0]
    assert item["label"] == "Echo called" and "said hello" in item["summary"]


def test_module_cannot_take_over_framework_routes() -> None:
    bad = APIRouter(prefix="/api/auth")

    @bad.get("/sneaky")
    def sneaky() -> dict:
        return {}

    with pytest.raises(ValueError, match="framework prefix"):
        create_app(make_config(modules=[Module(name="bad", routers=[bad])]))
    set_app_config(make_config())


def test_config_validation() -> None:
    with pytest.raises(ValueError):
        AppConfig(name="x", secret_providers=[SecretProvider("a", "A", ""), SecretProvider("a", "A", "")])
    with pytest.raises(ValueError):
        AppConfig(name="x", modules=[Module(name="m"), Module(name="m")])
    with pytest.raises(ValueError):
        AppConfig(name="x", max_users=0)
    with pytest.raises(ValueError):
        RetentionPolicy(max_total_days=30, backup_days=30)


def test_retention_includes_backup_age(admin) -> None:
    set_app_config(make_config(retention=RetentionPolicy(max_total_days=182, backup_days=120)))
    s = admin.client.get("/api/admin/settings").json()
    assert s["retention_days_max"] == 62 and s["retention_days"] == 62 and s["backup_days"] == 120
    r = admin.client.put("/api/admin/settings", json={"retention_days": 100})
    assert r.status_code == 422 and "120" in r.json()["message"]
    assert admin.client.put("/api/admin/settings", json={"retention_days": 30}).json()["retention_days"] == 30


def test_tightened_policy_clamps_stored_setting(admin, db, clock) -> None:
    admin.client.put("/api/admin/settings", json={"retention_days": 150})
    set_app_config(make_config(retention=RetentionPolicy(max_total_days=182, backup_days=100)))
    assert admin.client.get("/api/admin/settings").json()["retention_days"] == 82


def test_no_terms_means_no_terms_gate(client, clock, db) -> None:
    set_app_config(make_config(terms=None))
    from tests.conftest import onboard

    person = onboard(db, clock, "carol")
    assert person.client.get("/api/keys").status_code == 200
    assert client.get("/api/terms").status_code == 404
    assert client.get("/api/config").json()["terms_enabled"] is False


def test_raising_terms_version_asks_everyone_again(alice) -> None:
    from swf import TermsConfig

    set_app_config(make_config(terms=TermsConfig("2", "# New terms\n\nPlease read again.")))
    r = alice.client.get("/api/keys")
    assert r.status_code == 403 and r.json()["code"] == "terms_not_accepted"
    alice.client.post("/api/me/terms/accept", json={"version": "2"})
    assert alice.client.get("/api/keys").status_code == 200


def test_passkeys_off(alice, clock) -> None:
    set_app_config(make_config(passkeys="off"))
    assert alice.client.get("/api/me/passkeys").json() == {"enabled": False, "items": []}
    r = alice.client.post(
        "/api/me/passkeys/options", json={"password": alice.password, "totp_code": next_code(alice.secret, clock)}
    )
    assert r.status_code == 404
    assert alice.client.get("/api/config").json()["passkeys"] == "off"


def test_recovery_codes_off(client, clock, db) -> None:
    set_app_config(make_config(recovery_codes=False))
    from tests.conftest import onboard

    person = onboard(db, clock, "carol")
    assert person.recovery_codes is None
    assert person.client.get("/api/me/recovery-codes").json() == {"enabled": False, "remaining": 0}


def test_max_users_is_configurable(admin) -> None:
    set_app_config(make_config(max_users=2))
    assert admin.client.post("/api/admin/users", json={"username": "second"}).status_code == 201
    r = admin.client.post("/api/admin/users", json={"username": "third"})
    assert r.status_code == 409 and "at most 2" in r.json()["message"]
