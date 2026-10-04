"""A user's own API keys in the vault. Modules call `use()` to get a key for server-side work."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from swf import clock
from swf.appconfig import SecretProvider, get_app_config
from swf.models import User, UserSecret
from swf.security.vault import UserVault

SECRET_PURPOSE = "secret"  # noqa: S105 - a label, not a password


def provider(provider_id: str) -> SecretProvider | None:
    return next((p for p in get_app_config().secret_providers if p.id == provider_id), None)


def find(db: Session, user: User, provider_id: str) -> UserSecret | None:
    return db.scalar(select(UserSecret).where(UserSecret.user_id == user.id, UserSecret.provider == provider_id))


def store(db: Session, user: User, provider_id: str, secret: str, label: str | None) -> bool:
    """Add or replace a key. Returns True if an existing key was replaced."""
    nonce, ciphertext = UserVault.for_user(user).encrypt(secret.encode(), SECRET_PURPOSE, provider_id)
    existing = find(db, user, provider_id)
    if existing is None:
        db.add(
            UserSecret(
                user_id=user.id,
                provider=provider_id,
                label=label,
                ciphertext=ciphertext,
                nonce=nonce,
                created_at=clock.utcnow(),
            )
        )
        return False
    existing.ciphertext = ciphertext
    existing.nonce = nonce
    existing.label = label
    existing.created_at = clock.utcnow()
    existing.last_used_at = None
    return True


def reveal(user: User, row: UserSecret) -> str:
    return UserVault.for_user(user).decrypt(row.nonce, row.ciphertext, SECRET_PURPOSE, row.provider).decode()


def masked(user: User, row: UserSecret) -> str:
    return "••••" + reveal(user, row)[-4:]


def use(db: Session, user: User, provider_id: str) -> str | None:
    """Return the plaintext key for server-side use and note the use. Never send it to the browser."""
    row = find(db, user, provider_id)
    if row is None:
        return None
    row.last_used_at = clock.utcnow()
    db.commit()
    return reveal(user, row)
