"""Framework tables: users, sessions, vault, recovery codes, passkeys, audit, admin log, settings.

App tables subclass `swf.db.Base` too. User-owned tables must reference `users.id` with
`ondelete="CASCADE"` so account deletion and the retention purge remove them.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from swf import clock
from swf.db import Base, UTCDateTime

# Auto-increment big integers on PostgreSQL, plain INTEGER (rowid) on SQLite.
BigIntPK = BigInteger().with_variant(Integer, "sqlite")


def _now() -> datetime:
    # Looked up at call time so tests can patch swf.clock.utcnow.
    return clock.utcnow()


ROLE_USER = "user"
ROLE_ADMIN = "admin"

STAGE_TOTP_SETUP = "totp_setup"
STAGE_TOTP_VERIFY = "totp_verify"
STAGE_FULL = "full"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)

    # Wrapped per-user data key (nonce || AES-GCM ciphertext under the KEK).
    dek_wrapped: Mapped[bytes] = mapped_column(LargeBinary)

    # TOTP secret encrypted with the user's data key (nonce || ciphertext).
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    terms_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    terms_accepted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    theme: Mapped[str] = mapped_column(String(8), default="light")

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    secrets: Mapped[list["UserSecret"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    recovery_codes: Mapped[list["RecoveryCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    passkeys: Mapped[list["Passkey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    # SHA-256 of the cookie token; the token itself is never stored.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    stage: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    # Pending WebAuthn challenge (sign-in or passkey registration), single use, short-lived.
    challenge: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    challenge_purpose: Mapped[str | None] = mapped_column(String(16), nullable=True)
    challenge_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


class UserSecret(Base):
    __tablename__ = "user_secrets"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_user_secrets_user_provider"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="secrets")


class RecoveryCode(Base):
    """Single-use 2FA backup codes. Only a SHA-256 hash is stored (codes carry ~50 bits of entropy)."""

    __tablename__ = "recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="recovery_codes")


class Passkey(Base):
    """A WebAuthn credential. The public key is not secret; the private key never leaves the device."""

    __tablename__ = "passkeys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    transports: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    name: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="passkeys")


class AuditEvent(Base):
    """Append-only, per-user. Details are encrypted with the user's data key."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(48))
    details_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, index=True)

    user: Mapped[User] = relationship(back_populates="audit_events")


class AdminEvent(Base):
    """Append-only log of admin and system actions. Holds no user data."""

    __tablename__ = "admin_events"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(48))
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    target_username: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, index=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, onupdate=_now)
