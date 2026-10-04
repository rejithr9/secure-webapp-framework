"""The signed-in user's own account: profile, terms, preferences, activity, recovery codes,
passkeys and account deletion."""

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from swf import clock
from swf.appconfig import get_app_config
from swf.deps import DB, FullSession, ReadyUser, SignedInUser
from swf.errors import AppError
from swf.models import ROLE_ADMIN, AuditEvent, User
from swf.security import passwords
from swf.security.sessions import clear_cookies
from swf.services import audit, passkeys, recovery, signin, users

router = APIRouter(prefix="/api/me", tags=["me"])


def me_payload(user: User) -> dict:
    return {
        "username": user.username,
        "role": user.role,
        "theme": user.theme,
        "must_change_password": user.must_change_password,
        "terms_accepted": signin.terms_accepted(user),
        "next": signin.next_step(user),
    }


class TermsAcceptIn(BaseModel):
    version: str = Field(max_length=32)


class PreferencesIn(BaseModel):
    theme: Literal["light", "dark"]


class ReauthIn(BaseModel):
    password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)
    totp_code: str = Field(min_length=6, max_length=10)


class PasskeyIn(BaseModel):
    credential: dict[str, Any]
    name: str = Field(min_length=1, max_length=64)


@router.get("")
def get_me(user: SignedInUser) -> dict:
    return me_payload(user)


@router.post("/terms/accept")
def accept_terms(body: TermsAcceptIn, user: SignedInUser, db: DB) -> dict:
    terms = get_app_config().terms
    if terms is None:
        raise AppError(404, "no_terms", "This app has no terms to accept.")
    if body.version != terms.version:
        raise AppError(
            409,
            "terms_outdated",
            "The terms have changed since you opened this page. Reload the page and read them again.",
        )
    if user.terms_version != terms.version:
        user.terms_version = terms.version
        user.terms_accepted_at = clock.utcnow()
        audit.record(db, user, audit.TERMS_ACCEPTED, {"version": terms.version})
        db.commit()
    return me_payload(user)


@router.put("/preferences")
def set_preferences(body: PreferencesIn, user: SignedInUser, db: DB) -> dict:
    user.theme = body.theme
    db.commit()
    return me_payload(user)


@router.get("/audit")
def my_audit(
    user: ReadyUser,
    db: DB,
    limit: int = Query(default=50, ge=1, le=200),
    before_id: int | None = Query(default=None, ge=1),
) -> dict:
    stmt = select(AuditEvent).where(AuditEvent.user_id == user.id)
    if before_id is not None:
        stmt = stmt.where(AuditEvent.id < before_id)
    rows = db.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit + 1)).all()
    items = []
    for row in rows[:limit]:
        details = audit.read_details(user, row)
        items.append(
            {
                "id": row.id,
                "type": row.event_type,
                "label": audit.label_for(row.event_type),
                "summary": audit.summary_for(details),
                "details": details,
                "created_at": row.created_at.isoformat(),
            }
        )
    return {"items": items, "has_more": len(rows) > limit}


# ---- Recovery codes ----


@router.get("/recovery-codes")
def recovery_status(user: ReadyUser) -> dict:
    enabled = get_app_config().recovery_codes
    return {"enabled": enabled, "remaining": recovery.remaining(user) if enabled else 0}


@router.post("/recovery-codes")
def new_recovery_codes(body: ReauthIn, request: Request, user: ReadyUser, db: DB) -> dict:
    """Replace all recovery codes. The old ones stop working."""
    if not get_app_config().recovery_codes:
        raise AppError(404, "not_available", "Recovery codes are not used in this app.")
    signin.reauthenticate(db, request, user, body.password, body.totp_code)
    codes = recovery.generate(db, user)
    audit.record(db, user, audit.RECOVERY_CODES_CREATED)
    db.commit()
    return {"codes": codes}


# ---- Passkeys ----


def _passkeys_on() -> None:
    if get_app_config().passkeys == "off":
        raise AppError(404, "not_available", "Passkeys are not used in this app.")


@router.get("/passkeys")
def list_passkeys(user: ReadyUser) -> dict:
    enabled = get_app_config().passkeys != "off"
    return {
        "enabled": enabled,
        "items": [
            {
                "id": str(pk.id),
                "name": pk.name,
                "created_at": pk.created_at.isoformat(),
                "last_used_at": pk.last_used_at.isoformat() if pk.last_used_at else None,
            }
            for pk in sorted(user.passkeys, key=lambda p: p.created_at)
        ]
        if enabled
        else [],
    }


@router.post("/passkeys/options")
def passkey_registration_options(
    body: ReauthIn, request: Request, session: FullSession, user: ReadyUser, db: DB
) -> dict:
    """Step 1 of adding a passkey. Confirming with password + code stops a stolen session adding one."""
    _passkeys_on()
    signin.reauthenticate(db, request, user, body.password, body.totp_code)
    options = passkeys.registration_options(session, user)
    db.commit()
    return options


@router.post("/passkeys", status_code=201)
def add_passkey(body: PasskeyIn, session: FullSession, user: ReadyUser, db: DB) -> dict:
    _passkeys_on()
    if len(user.passkeys) >= 10:
        raise AppError(409, "too_many_passkeys", "You can have up to 10 passkeys. Remove one you no longer use first.")
    name = body.name.strip() or "Passkey"
    try:
        passkey = passkeys.register(db, session, user, body.credential, name)
    except passkeys.PasskeyError:
        db.commit()  # the challenge is used up either way
        raise AppError(
            400,
            "passkey_not_added",
            "We couldn't add that passkey. Please start again and follow your device's prompts.",
        ) from None
    audit.record(db, user, audit.PASSKEY_ADDED, {"name": name})
    db.commit()
    return {"id": str(passkey.id), "name": passkey.name}


@router.delete("/passkeys/{passkey_id}", status_code=204)
def remove_passkey(passkey_id: uuid.UUID, user: ReadyUser, db: DB) -> Response:
    passkey = next((pk for pk in user.passkeys if pk.id == passkey_id), None)
    if passkey is None:
        raise AppError(404, "no_passkey", "That passkey doesn't exist any more. Reload the page.")
    user.passkeys.remove(passkey)
    audit.record(db, user, audit.PASSKEY_REMOVED, {"name": passkey.name})
    db.commit()
    return Response(status_code=204)


# ---- Account deletion ----


@router.delete("", status_code=204)
def delete_my_account(body: ReauthIn, request: Request, user: SignedInUser, db: DB) -> Response:
    """Delete the account and all its data. Needs the password and a fresh authenticator code."""
    others = db.scalar(select(User).where(User.id != user.id).limit(1))
    if user.role == ROLE_ADMIN and users.active_admin_count(db) == 1 and others:
        raise AppError(
            409,
            "last_admin",
            "You are the only administrator. Create another admin account first, then delete this one.",
        )
    signin.reauthenticate(db, request, user, body.password, body.totp_code, step="account_deletion")
    audit.record_admin(db, "account_self_deleted", actor=None, target=user)
    users.delete_user(db, user)
    db.commit()
    response = Response(status_code=204)
    clear_cookies(response)
    return response
