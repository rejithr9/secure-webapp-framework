"""Admin area: account management and settings only. No access to any user's data."""

import uuid
from typing import Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from swf import clock
from swf.appconfig import get_app_config
from swf.deps import DB, AdminUser
from swf.errors import AppError
from swf.models import AdminEvent, User
from swf.security.sessions import revoke_all_sessions
from swf.services import audit, settings_store, signin, users

router = APIRouter(prefix="/api/admin", tags=["admin"])


class CreateUserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    role: Literal["user", "admin"] = "user"


class SettingsIn(BaseModel):
    retention_days: int


def _status(user: User) -> str:
    if user.deactivated_at is not None:
        return "deactivated"
    if signin.is_locked(user):
        return "locked"
    if user.must_change_password or not user.totp_enabled:
        return "setup_pending"
    return "active"


def user_row(user: User) -> dict:
    """The only user fields the admin ever sees."""
    return {
        "id": str(user.id),
        "username": user.username,
        "role": user.role,
        "status": _status(user),
        "created_at": user.created_at.isoformat(),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _target(db: DB, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "user_not_found", "That account doesn't exist any more. Reload the list.")
    return user


@router.get("/users")
def list_users(admin: AdminUser, db: DB) -> dict:
    rows = db.scalars(select(User).order_by(User.created_at)).all()
    return {"items": [user_row(u) for u in rows], "max_users": get_app_config().max_users}


@router.post("/users", status_code=201)
def create_user(body: CreateUserIn, admin: AdminUser, db: DB) -> dict:
    user, initial_password = users.create_user(db, body.username, body.role)
    audit.record_admin(db, "user_created", actor=admin, target=user, details={"role": user.role})
    db.commit()
    return {"user": user_row(user), "initial_password": initial_password}


@router.post("/users/{user_id}/reset")
def reset_user(user_id: uuid.UUID, admin: AdminUser, db: DB) -> dict:
    user = _target(db, user_id)
    if user.id == admin.id:
        raise AppError(409, "cannot_reset_self", "You can't reset your own sign-in here. Use 'My account' instead.")
    initial_password = users.reset_sign_in(db, user)
    audit.record_admin(db, "user_sign_in_reset", actor=admin, target=user)
    db.commit()
    return {"user": user_row(user), "initial_password": initial_password}


@router.post("/users/{user_id}/deactivate")
def deactivate_user(user_id: uuid.UUID, admin: AdminUser, db: DB) -> dict:
    user = _target(db, user_id)
    if user.id == admin.id:
        raise AppError(409, "cannot_deactivate_self", "You can't deactivate your own account.")
    if user.deactivated_at is None:
        user.deactivated_at = clock.utcnow()
        revoke_all_sessions(db, user.id)
        audit.record_admin(db, "user_deactivated", actor=admin, target=user)
        db.commit()
    return {"user": user_row(user)}


@router.post("/users/{user_id}/reactivate")
def reactivate_user(user_id: uuid.UUID, admin: AdminUser, db: DB) -> dict:
    user = _target(db, user_id)
    if user.deactivated_at is not None:
        user.deactivated_at = None
        audit.record_admin(db, "user_reactivated", actor=admin, target=user)
        db.commit()
    return {"user": user_row(user)}


def _settings_payload(db: DB) -> dict:
    policy = get_app_config().retention
    return {
        "retention_days": settings_store.retention_days(db),
        "retention_days_min": policy.min_days,
        "retention_days_max": policy.max_setting,
        "retention_max_total_days": policy.max_total_days,
        "backup_days": policy.backup_days,
    }


@router.get("/settings")
def get_admin_settings(admin: AdminUser, db: DB) -> dict:
    return _settings_payload(db)


@router.put("/settings")
def put_admin_settings(body: SettingsIn, admin: AdminUser, db: DB) -> dict:
    policy = get_app_config().retention
    if not policy.min_days <= body.retention_days <= policy.max_setting:
        raise AppError(
            422,
            "retention_out_of_range",
            f"Choose between {policy.min_days} and {policy.max_setting} days. Backups keep data for up to "
            f"{policy.backup_days} more days, and the total may not exceed {policy.max_total_days} days.",
        )
    old = settings_store.retention_days(db)
    if old != body.retention_days:
        settings_store.put(db, settings_store.RETENTION_DAYS, body.retention_days)
        audit.record_admin(
            db, "settings_changed", actor=admin, details={"retention_days": {"from": old, "to": body.retention_days}}
        )
        db.commit()
    return _settings_payload(db)


@router.get("/events")
def admin_events(admin: AdminUser, db: DB, limit: int = Query(default=100, ge=1, le=500)) -> dict:
    rows = db.scalars(select(AdminEvent).order_by(AdminEvent.id.desc()).limit(limit)).all()
    return {
        "items": [
            {
                "id": r.id,
                "action": r.action,
                "actor": r.actor_username or "system",
                "target": r.target_username,
                "details": r.details,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
    }
