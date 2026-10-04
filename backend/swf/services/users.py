"""Creating, resetting and deleting user accounts."""

import re
import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from swf import clock
from swf.appconfig import get_app_config
from swf.errors import AppError
from swf.models import ROLE_ADMIN, ROLE_USER, User
from swf.security import passwords
from swf.security.sessions import revoke_all_sessions
from swf.security.vault import new_wrapped_dek
from swf.services import audit, settings_store

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


def normalise_username(username: str) -> str:
    return username.strip().lower()


def create_user(db: Session, username: str, role: str) -> tuple[User, str]:
    """Create a user with a one-time initial password. Returns (user, initial_password)."""
    username = normalise_username(username)
    if not USERNAME_RE.match(username):
        raise AppError(
            422,
            "invalid_username",
            "Usernames are 3 to 32 characters: lowercase letters, digits, dots, dashes or underscores, "
            "starting with a letter or digit.",
        )
    if role not in (ROLE_USER, ROLE_ADMIN):
        raise AppError(422, "invalid_role", "Choose the role 'user' or 'admin'.")
    max_users = get_app_config().max_users
    if (db.scalar(select(func.count()).select_from(User)) or 0) >= max_users:
        raise AppError(
            409,
            "user_limit_reached",
            f"The app allows at most {max_users} accounts. Deactivate and remove an old account first.",
        )
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise AppError(409, "username_taken", "That username is already in use. Choose another one.")

    initial_password = passwords.generate_initial_password()
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        username=username,
        role=role,
        password_hash=passwords.hash_password(initial_password),
        must_change_password=True,
        dek_wrapped=new_wrapped_dek(user_id),
        created_at=clock.utcnow(),
    )
    db.add(user)
    return user, initial_password


def reset_sign_in(db: Session, user: User) -> str:
    """New one-time password; 2FA, recovery codes and passkeys cleared (forces re-enrolment);
    lockout cleared; all sessions ended."""
    initial_password = passwords.generate_initial_password()
    user.password_hash = passwords.hash_password(initial_password)
    user.must_change_password = True
    user.totp_secret_enc = None
    user.totp_enabled = False
    user.totp_last_step = None
    user.recovery_codes.clear()
    user.passkeys.clear()
    user.failed_login_count = 0
    user.locked_until = None
    revoke_all_sessions(db, user.id)
    return initial_password


def active_admin_count(db: Session) -> int:
    return (
        db.scalar(select(func.count()).select_from(User).where(User.role == ROLE_ADMIN, User.deactivated_at.is_(None)))
        or 0
    )


def delete_user(db: Session, user: User) -> None:
    """Delete a user and every row that belongs to them."""
    db.delete(user)


def purge_expired(db: Session) -> list[str]:
    """Delete all data of users deactivated longer than the retention period."""
    days = settings_store.retention_days(db)
    cutoff = clock.utcnow() - timedelta(days=days)
    expired = db.scalars(select(User).where(User.deactivated_at.is_not(None), User.deactivated_at <= cutoff)).all()
    names = [u.username for u in expired]
    for user in expired:
        audit.record_admin(db, "retention_purge", actor=None, target=user, details={"retention_days": days})
        delete_user(db, user)
    db.commit()
    return names
