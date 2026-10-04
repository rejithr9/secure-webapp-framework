"""Framework tables: users, sessions, key vault, recovery codes, passkeys, audit trail, admin log, settings.

Revision ID: swf_0001
Revises:
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "swf_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = ("swf",)
depends_on: str | Sequence[str] | None = None

BigIntPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def user_fk() -> sa.Column:
    return sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)


# PostgreSQL only: audit rows can never be edited; the admin log can never be edited or deleted.
# (Audit rows are still deleted together with their user, on self-deletion or retention purge.)
APPEND_ONLY_SQL = """
CREATE OR REPLACE FUNCTION swf_forbid_change() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed (append-only table)', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION swf_forbid_change();
CREATE TRIGGER admin_events_no_update_delete BEFORE UPDATE OR DELETE ON admin_events
  FOR EACH ROW EXECUTE FUNCTION swf_forbid_change();
"""


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("username", sa.String(32), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("dek_wrapped", sa.LargeBinary(), nullable=False),
        sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False),
        sa.Column("totp_last_step", sa.BigInteger(), nullable=True),
        sa.Column("terms_version", sa.String(16), nullable=True),
        ts("terms_accepted_at", nullable=True),
        sa.Column("theme", sa.String(8), nullable=False),
        ts("created_at"),
        ts("last_login_at", nullable=True),
        ts("deactivated_at", nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        ts("locked_until", nullable=True),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        user_fk(),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("stage", sa.String(16), nullable=False),
        ts("created_at"),
        ts("last_seen_at"),
        ts("expires_at"),
        sa.Column("challenge", sa.LargeBinary(), nullable=True),
        sa.Column("challenge_purpose", sa.String(16), nullable=True),
        ts("challenge_expires_at", nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_table(
        "user_secrets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        user_fk(),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("label", sa.String(64), nullable=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        ts("created_at"),
        ts("last_used_at", nullable=True),
        sa.UniqueConstraint("user_id", "provider", name="uq_user_secrets_user_provider"),
    )
    op.create_index("ix_user_secrets_user_id", "user_secrets", ["user_id"])
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        user_fk(),
        sa.Column("code_hash", sa.String(64), nullable=False),
        ts("created_at"),
        ts("used_at", nullable=True),
    )
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])
    op.create_table(
        "passkeys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        user_fk(),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("transports", sa.JSON(), nullable=True),
        sa.Column("name", sa.String(64), nullable=False),
        ts("created_at"),
        ts("last_used_at", nullable=True),
    )
    op.create_index("ix_passkeys_user_id", "passkeys", ["user_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", BigIntPK, primary_key=True, autoincrement=True),
        user_fk(),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("details_enc", sa.LargeBinary(), nullable=True),
        ts("created_at"),
    )
    op.create_index("ix_audit_events_user_id", "audit_events", ["user_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_table(
        "admin_events",
        sa.Column("id", BigIntPK, primary_key=True, autoincrement=True),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("actor_username", sa.String(32), nullable=True),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("target_user_id", sa.Uuid(), nullable=True),
        sa.Column("target_username", sa.String(32), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        ts("created_at"),
    )
    op.create_index("ix_admin_events_created_at", "admin_events", ["created_at"])
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
        ts("updated_at"),
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(APPEND_ONLY_SQL)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS admin_events_no_update_delete ON admin_events")
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS swf_forbid_change()")
    for table in (
        "app_settings",
        "admin_events",
        "audit_events",
        "passkeys",
        "recovery_codes",
        "user_secrets",
        "sessions",
        "users",
    ):
        op.drop_table(table)
