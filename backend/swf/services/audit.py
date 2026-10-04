"""Audit trail (per user, encrypted) and admin log (system-wide, no user data).

Never put passwords, codes, keys or tokens into either log. Modules record their own
event types with `record()` and register labels through `Module.audit_labels`.
"""

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from swf import clock
from swf.appconfig import get_app_config
from swf.models import AdminEvent, AuditEvent, User
from swf.security.vault import UserVault

AUDIT_PURPOSE = "audit"

# Framework event types (user audit trail)
SIGN_IN_SUCCESS = "sign_in_success"
SIGN_IN_FAILED = "sign_in_failed"
ACCOUNT_LOCKED = "account_locked"
TOTP_ENABLED = "totp_enabled"
TERMS_ACCEPTED = "terms_accepted"
KEY_ADDED = "key_added"
KEY_REPLACED = "key_replaced"
KEY_REMOVED = "key_removed"
PASSWORD_CHANGED = "password_changed"  # noqa: S105 - a label, not a password
SIGNED_OUT = "signed_out"
RECOVERY_CODES_CREATED = "recovery_codes_created"
RECOVERY_CODE_USED = "recovery_code_used"
PASSKEY_ADDED = "passkey_added"
PASSKEY_REMOVED = "passkey_removed"

FRAMEWORK_LABELS = {
    SIGN_IN_SUCCESS: "Signed in",
    SIGN_IN_FAILED: "Failed sign-in attempt",
    ACCOUNT_LOCKED: "Account locked after too many failed attempts",
    TOTP_ENABLED: "Two-factor authentication turned on",
    TERMS_ACCEPTED: "Terms accepted",
    KEY_ADDED: "Key added",
    KEY_REPLACED: "Key replaced",
    KEY_REMOVED: "Key removed",
    PASSWORD_CHANGED: "Password changed",
    SIGNED_OUT: "Signed out",
    RECOVERY_CODES_CREATED: "New recovery codes created",
    RECOVERY_CODE_USED: "Signed in with a recovery code",
    PASSKEY_ADDED: "Passkey added",
    PASSKEY_REMOVED: "Passkey removed",
}

_STEP_NAMES = {
    "password": "wrong password",
    "code": "wrong authenticator code",
    "recovery_code": "wrong recovery code",
    "passkey": "passkey not accepted",
    "password_change": "wrong password while changing password",
    "account_deletion": "wrong password while deleting the account",
    "reauth": "wrong password or code while confirming an action",
}


def label_for(event_type: str) -> str:
    for module in get_app_config().modules:
        if event_type in module.audit_labels:
            return module.audit_labels[event_type]
    return FRAMEWORK_LABELS.get(event_type, event_type.replace("_", " ").capitalize())


def summary_for(details: dict[str, Any] | None) -> str:
    """A short plain-English line describing an event's details."""
    if not details:
        return ""
    providers = {p.id: p.name for p in get_app_config().secret_providers}
    parts: list[str] = []
    if isinstance(details.get("provider"), str):
        parts.append(providers.get(details["provider"], details["provider"]))
    if isinstance(details.get("name"), str):
        parts.append(f"“{details['name']}”")
    if isinstance(details.get("step"), str):
        parts.append(_STEP_NAMES.get(details["step"], details["step"]))
    if isinstance(details.get("method"), str):
        parts.append(f"with {details['method']}")
    if isinstance(details.get("version"), str):
        parts.append(f"version {details['version']}")
    if isinstance(details.get("remaining"), int):
        parts.append(f"{details['remaining']} recovery codes left")
    if isinstance(details.get("minutes"), int):
        parts.append(f"for {details['minutes']} minutes")
    if isinstance(details.get("summary"), str):
        parts.append(details["summary"])
    if isinstance(details.get("ip"), str):
        parts.append(f"from {details['ip']}")
    return " · ".join(parts)


def request_context(request: Request) -> dict[str, Any]:
    client = request.client.host if request.client else None
    agent = request.headers.get("user-agent", "")[:200]
    return {"ip": client, "browser": agent}


def record(db: Session, user: User, event_type: str, details: dict[str, Any] | None = None) -> None:
    blob = UserVault.for_user(user).seal_json(details, AUDIT_PURPOSE) if details else None
    db.add(AuditEvent(user_id=user.id, event_type=event_type, details_enc=blob, created_at=clock.utcnow()))


def read_details(user: User, event: AuditEvent) -> dict[str, Any] | None:
    if event.details_enc is None:
        return None
    return UserVault.for_user(user).open_json(event.details_enc, AUDIT_PURPOSE)


def record_admin(
    db: Session,
    action: str,
    actor: User | None,
    target: User | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AdminEvent(
            actor_user_id=actor.id if actor else None,
            actor_username=actor.username if actor else None,
            action=action,
            target_user_id=target.id if target else None,
            target_username=target.username if target else None,
            details=details,
            created_at=clock.utcnow(),
        )
    )
