"""Sign-in bookkeeping: lockout, completing a sign-in, and what the user must do next."""

from datetime import timedelta

from fastapi import Request, Response
from sqlalchemy.orm import Session

from swf import clock
from swf.appconfig import get_app_config
from swf.config import get_settings
from swf.errors import AppError, sign_in_failed, wrong_code
from swf.models import STAGE_FULL, User, UserSession
from swf.security import passwords, totp
from swf.security.sessions import create_session, revoke_all_sessions
from swf.security.vault import UserVault
from swf.services import audit

TOTP_PURPOSE = "totp"

NEXT_CHANGE_PASSWORD = "change_password"  # noqa: S105 - a label, not a password
NEXT_ACCEPT_TERMS = "accept_terms"
NEXT_DASHBOARD = "dashboard"


def is_locked(user: User) -> bool:
    return user.locked_until is not None and clock.utcnow() < user.locked_until


def register_failure(db: Session, user: User, request: Request, step: str) -> bool:
    """Count a wrong password or code. Returns True if the account is now locked.

    The counter is only reset after a *complete* sign-in, so a known password cannot be
    used to reset the counter while guessing codes.
    """
    settings = get_settings()
    user.failed_login_count += 1
    audit.record(db, user, audit.SIGN_IN_FAILED, {**audit.request_context(request), "step": step})
    locked = user.failed_login_count >= settings.lockout_threshold
    if locked:
        user.locked_until = clock.utcnow() + timedelta(minutes=settings.lockout_minutes)
        user.failed_login_count = 0
        audit.record(db, user, audit.ACCOUNT_LOCKED, {"minutes": settings.lockout_minutes})
        revoke_all_sessions(db, user.id)
    db.commit()
    return locked


def terms_accepted(user: User) -> bool:
    terms = get_app_config().terms
    return terms is None or user.terms_version == terms.version


def next_step(user: User) -> str:
    if user.must_change_password:
        return NEXT_CHANGE_PASSWORD
    if not terms_accepted(user):
        return NEXT_ACCEPT_TERMS
    return NEXT_DASHBOARD


def complete_sign_in(
    db: Session, request: Request, response: Response, pending: UserSession, user: User, method: str
) -> str:
    """Swap the pending session for a full one (new token: no session fixation)."""
    db.delete(pending)
    create_session(db, response, user, STAGE_FULL)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = clock.utcnow()
    audit.record(db, user, audit.SIGN_IN_SUCCESS, {**audit.request_context(request), "method": method})
    db.commit()
    return next_step(user)


def check_code(db: Session, request: Request, user: User, code: str) -> int:
    """Return the matched TOTP step, or count a failure and raise.

    The step is remembered on the user (committed with the caller's changes) so the same
    code can never be used twice.
    """
    if is_locked(user) or user.totp_secret_enc is None:
        raise sign_in_failed()
    secret = UserVault.for_user(user).open(user.totp_secret_enc, TOTP_PURPOSE).decode()
    step = totp.matching_step(secret, code, clock.utcnow(), user.totp_last_step)
    if step is None:
        if register_failure(db, user, request, step="code"):
            raise sign_in_failed()
        raise wrong_code()
    user.totp_last_step = step
    return step


def reauthenticate(db: Session, request: Request, user: User, password: str, code: str, step: str = "reauth") -> None:
    """Confirm a sensitive action with the password and a fresh authenticator code.

    Wrong answers count towards the lockout; a lockout ends every session.
    """
    if is_locked(user):
        raise sign_in_failed()
    if not passwords.verify_password(user.password_hash, password):
        if register_failure(db, user, request, step=step):
            raise sign_in_failed()
        raise AppError(400, "wrong_password", "Your password is not correct. Please try again.")
    check_code(db, request, user, code)
