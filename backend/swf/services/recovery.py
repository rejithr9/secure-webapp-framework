"""2FA recovery codes: single-use backup codes for when the authenticator app isn't at hand."""

import hashlib
import hmac
import secrets

from sqlalchemy.orm import Session

from swf import clock
from swf.models import RecoveryCode, User

CODE_COUNT = 10
# No 0/O, 1/I/L: easy to read from paper. 10 characters ≈ 50 bits of entropy.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _normalise(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _hash(user: User, code: str) -> str:
    return hashlib.sha256(f"{user.id}:{_normalise(code)}".encode()).hexdigest()


def generate(db: Session, user: User) -> list[str]:
    """Replace all of a user's recovery codes. Returns the new codes (shown to the user once)."""
    user.recovery_codes.clear()
    codes = []
    for _ in range(CODE_COUNT):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
        user.recovery_codes.append(RecoveryCode(code_hash=_hash(user, raw), created_at=clock.utcnow()))
    db.flush()
    return codes


def remaining(user: User) -> int:
    return sum(1 for c in user.recovery_codes if c.used_at is None)


def consume(user: User, code: str) -> bool:
    """Mark a matching unused code as used. Returns False if no unused code matches."""
    if len(_normalise(code)) != 10:
        return False
    wanted = _hash(user, code)
    for row in user.recovery_codes:
        if row.used_at is None and hmac.compare_digest(row.code_hash, wanted):
            row.used_at = clock.utcnow()
            return True
    return False
