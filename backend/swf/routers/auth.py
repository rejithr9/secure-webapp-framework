"""Sign-in: password, then an authenticator code, a passkey or a recovery code. Sign-out, password change."""

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from swf.appconfig import get_app_config
from swf.config import get_settings
from swf.deps import DB, AnySession, FullSession, OptionalSession, SignedInUser
from swf.errors import AppError, sign_in_failed
from swf.models import STAGE_FULL, STAGE_TOTP_SETUP, STAGE_TOTP_VERIFY, User, UserSession
from swf.routers.me import me_payload
from swf.security import passwords, totp
from swf.security.ratelimit import auth_rate_limit
from swf.security.sessions import (
    CSRF_COOKIE,
    create_session,
    end_session,
    issue_csrf_cookie,
    revoke_all_sessions,
)
from swf.security.vault import UserVault
from swf.services import audit, passkeys, recovery, signin
from swf.services.signin import TOTP_PURPOSE
from swf.services.users import normalise_username

router = APIRouter(prefix="/api/auth", tags=["auth"])
limited = [Depends(auth_rate_limit)]


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=16)


class CredentialIn(BaseModel):
    credential: dict[str, Any]


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)
    totp_code: str = Field(min_length=6, max_length=10)


def _passkeys_on() -> bool:
    return get_app_config().passkeys != "off"


def _require_stage(session: UserSession, stage: str) -> None:
    if session.stage != stage:
        raise AppError(409, "wrong_step", "This sign-in step doesn't apply right now. Please sign in again.")


@router.get("/session")
def session_state(request: Request, response: Response, session: OptionalSession) -> dict:
    """Where the browser is in the sign-in flow. Also hands out the CSRF cookie."""
    if CSRF_COOKIE not in request.cookies:
        issue_csrf_cookie(response)
    if session is None:
        return {"stage": "signed_out", "user": None}
    state: dict[str, Any] = {"stage": session.stage, "user": None}
    if session.stage == STAGE_FULL:
        state["user"] = me_payload(session.user)
    elif session.stage == STAGE_TOTP_VERIFY:
        user = session.user
        state["passkey_available"] = _passkeys_on() and bool(user.passkeys)
        state["recovery_available"] = get_app_config().recovery_codes and recovery.remaining(user) > 0
    return state


@router.post("/login", dependencies=limited)
def login(body: LoginIn, request: Request, response: Response, db: DB, current: OptionalSession) -> dict:
    user = db.scalar(select(User).where(User.username == normalise_username(body.username)))
    password_ok = passwords.verify_password(user.password_hash if user else None, body.password)
    if user is None or user.deactivated_at is not None or signin.is_locked(user):
        raise sign_in_failed()
    if not password_ok:
        signin.register_failure(db, user, request, step="password")
        raise sign_in_failed()

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)
    if current is not None:
        db.delete(current)
    stage = STAGE_TOTP_VERIFY if user.totp_enabled else STAGE_TOTP_SETUP
    create_session(db, response, user, stage)
    db.commit()
    return {"next": stage}


@router.get("/totp/setup")
def totp_setup(session: AnySession, db: DB) -> dict:
    """First sign-in: create (once) the secret for the authenticator app and show it as a QR code."""
    if session.stage != STAGE_TOTP_SETUP:
        raise AppError(409, "totp_already_set_up", "Two-factor authentication is already set up for this account.")
    user = session.user
    vault = UserVault.for_user(user)
    if user.totp_secret_enc is None:
        secret = totp.new_secret()
        user.totp_secret_enc = vault.seal(secret.encode(), TOTP_PURPOSE)
        db.commit()
    else:
        secret = vault.open(user.totp_secret_enc, TOTP_PURPOSE).decode()
    uri = totp.provisioning_uri(secret, user.username, get_app_config().name)
    return {"otpauth_uri": uri, "qr_svg": totp.qr_svg_data_uri(uri), "secret": secret}


@router.post("/totp/enable", dependencies=limited)
def totp_enable(body: CodeIn, request: Request, response: Response, session: AnySession, db: DB) -> dict:
    if session.stage != STAGE_TOTP_SETUP:
        raise AppError(409, "totp_already_set_up", "Two-factor authentication is already set up for this account.")
    user = session.user
    signin.check_code(db, request, user, body.code)
    user.totp_enabled = True
    audit.record(db, user, audit.TOTP_ENABLED)
    codes = None
    if get_app_config().recovery_codes:
        codes = recovery.generate(db, user)
        audit.record(db, user, audit.RECOVERY_CODES_CREATED)
    result: dict[str, Any] = {"next": signin.complete_sign_in(db, request, response, session, user, "authenticator")}
    if codes:
        result["recovery_codes"] = codes
    return result


@router.post("/totp/verify", dependencies=limited)
def totp_verify(body: CodeIn, request: Request, response: Response, session: AnySession, db: DB) -> dict:
    _require_stage(session, STAGE_TOTP_VERIFY)
    user = session.user
    signin.check_code(db, request, user, body.code)
    return {"next": signin.complete_sign_in(db, request, response, session, user, "authenticator")}


@router.post("/recovery", dependencies=limited)
def recovery_sign_in(body: CodeIn, request: Request, response: Response, session: AnySession, db: DB) -> dict:
    """Second step with a single-use recovery code instead of the authenticator app."""
    _require_stage(session, STAGE_TOTP_VERIFY)
    if not get_app_config().recovery_codes:
        raise AppError(404, "not_available", "Recovery codes are not used in this app.")
    user = session.user
    if signin.is_locked(user):
        raise sign_in_failed()
    if not recovery.consume(user, body.code):
        if signin.register_failure(db, user, request, step="recovery_code"):
            raise sign_in_failed()
        raise AppError(
            401, "wrong_recovery_code", "That recovery code didn't work. Each code works once. Check it and try again."
        )
    left = recovery.remaining(user)
    audit.record(db, user, audit.RECOVERY_CODE_USED, {**audit.request_context(request), "remaining": left})
    nxt = signin.complete_sign_in(db, request, response, session, user, "recovery code")
    return {"next": nxt, "recovery_codes_left": left}


@router.post("/passkey/options", dependencies=limited)
def passkey_options(session: AnySession, db: DB) -> dict:
    _require_stage(session, STAGE_TOTP_VERIFY)
    if not _passkeys_on() or not session.user.passkeys:
        raise AppError(404, "no_passkey", "There is no passkey for this account. Use your authenticator app.")
    options = passkeys.authentication_options(session, session.user)
    db.commit()
    return options


@router.post("/passkey/verify", dependencies=limited)
def passkey_verify(body: CredentialIn, request: Request, response: Response, session: AnySession, db: DB) -> dict:
    _require_stage(session, STAGE_TOTP_VERIFY)
    user = session.user
    if not _passkeys_on() or signin.is_locked(user):
        raise sign_in_failed()
    try:
        passkey = passkeys.authenticate(session, user, body.credential)
    except passkeys.PasskeyError:
        db.commit()  # the challenge is used up either way
        if signin.register_failure(db, user, request, step="passkey"):
            raise sign_in_failed() from None
        raise AppError(
            401, "passkey_failed", "Your passkey wasn't accepted. Try again, or use your authenticator app."
        ) from None
    return {"next": signin.complete_sign_in(db, request, response, session, user, f"passkey “{passkey.name}”")}


@router.post("/logout", status_code=204)
def logout(request: Request, db: DB, session: OptionalSession) -> Response:
    response = Response(status_code=204)
    if session is not None and session.stage == STAGE_FULL:
        audit.record(db, session.user, audit.SIGNED_OUT)
        db.commit()
    end_session(db, request, response)
    return response


@router.post("/password", dependencies=limited)
def change_password(body: PasswordChangeIn, request: Request, session: FullSession, user: SignedInUser, db: DB) -> dict:
    if not passwords.verify_password(user.password_hash, body.current_password):
        if signin.register_failure(db, user, request, step="password_change"):
            raise sign_in_failed()
        raise AppError(400, "wrong_password", "Your current password is not correct. Please try again.")

    # Check the new password before using up the authenticator code.
    problem = passwords.password_problem(body.new_password, user.username, get_settings().password_min_length)
    if problem is None and passwords.verify_password(user.password_hash, body.new_password):
        problem = "Your new password must be different from your current one."
    if problem:
        raise AppError(422, "weak_password", problem)

    signin.check_code(db, request, user, body.totp_code)
    user.password_hash = passwords.hash_password(body.new_password)
    user.must_change_password = False
    revoke_all_sessions(db, user.id, except_id=session.id)
    audit.record(db, user, audit.PASSWORD_CHANGED)
    db.commit()
    return {"next": signin.next_step(user)}
