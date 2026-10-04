"""The example app's own behaviour, plus the framework guarantees it relies on."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, func, select
from swf import migrate
from swf.db import Base
from swf.testing import new_client, next_code

from notes_app.main import MIGRATIONS, MODEL_MODULES, app
from notes_app.models import Note


def test_add_list_delete_note(alice) -> None:
    r = alice.client.post("/api/notes", json={"body": "Buy milk"})
    assert r.status_code == 201
    note_id = r.json()["id"]
    assert [n["body"] for n in alice.client.get("/api/notes").json()["items"]] == ["Buy milk"]
    assert alice.client.delete(f"/api/notes/{note_id}").status_code == 204
    assert alice.client.get("/api/notes").json()["items"] == []
    labels = [i["label"] for i in alice.client.get("/api/me/audit").json()["items"]]
    assert "Note added" in labels and "Note deleted" in labels


def test_notes_need_sign_in(db) -> None:
    assert new_client(app).get("/api/notes").status_code == 401


def test_users_only_see_their_own_notes(alice, bob) -> None:
    note_id = alice.client.post("/api/notes", json={"body": "Alice's secret"}).json()["id"]
    assert bob.client.get("/api/notes").json()["items"] == []
    assert bob.client.delete(f"/api/notes/{note_id}").status_code == 404
    assert len(alice.client.get("/api/notes").json()["items"]) == 1


def test_notes_are_encrypted_at_rest(alice, db) -> None:
    alice.client.post("/api/notes", json={"body": "very private words"})
    row = db.scalar(select(Note))
    assert b"very private words" not in row.body_enc


def test_deleting_the_account_deletes_the_notes(alice, db, clock) -> None:
    alice.client.post("/api/notes", json={"body": "x"})
    r = alice.client.request(
        "DELETE", "/api/me", json={"password": alice.password, "totp_code": next_code(alice.secret, clock)}
    )
    assert r.status_code == 204
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Note)) == 0


def test_retention_includes_backup_days(db, clock) -> None:
    from swf.testing import onboard

    admin = onboard(app, db, clock, "boss", role="admin")
    settings = admin.client.get("/api/admin/settings").json()
    # The Notes app keeps backups for 30 days, so live retention may be at most 182 - 30 days.
    assert settings["retention_days_max"] == 152 and settings["backup_days"] == 30


def test_migrations_build_framework_and_app_tables(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'notes.db'}"
    migrate.upgrade(url, MIGRATIONS, MODEL_MODULES)
    engine = create_engine(url)
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
    engine.dispose()
