"""The server command line."""

import io
import sys

from sqlalchemy import select

from swf.cli import main
from swf.models import AdminEvent, User
from tests.conftest import make_config


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_create_admin_refuses_without_a_terminal(engine, db, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert main(make_config(), ["create-admin", "owner"]) == 2
    assert db.scalar(select(User)) is None


def test_create_admin_prints_password_once_to_a_terminal(engine, db, monkeypatch) -> None:
    out = _Terminal()
    monkeypatch.setattr(sys, "stdout", out)
    assert main(make_config(), ["create-admin", "owner"]) == 0
    user = db.scalar(select(User).where(User.username == "owner"))
    assert user is not None and user.role == "admin" and user.must_change_password
    assert "One-time password" in out.getvalue()
    assert db.scalar(select(AdminEvent).where(AdminEvent.action == "user_created")).details["via"] == "cli"


def test_create_admin_can_be_forced_for_automation(engine, db, monkeypatch) -> None:
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert main(make_config(), ["create-admin", "owner", "--allow-non-interactive"]) == 0


def test_generate_master_key(monkeypatch) -> None:
    import base64

    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert main(make_config(), ["generate-master-key"]) == 0
    assert len(base64.urlsafe_b64decode(out.getvalue().strip())) == 32
