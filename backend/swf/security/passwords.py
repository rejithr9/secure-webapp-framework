"""Argon2id password hashing and password rules."""

import secrets
import string

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(type=Type.ID)

# Used to spend the same time on unknown usernames as on real ones.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MAX_PASSWORD_LENGTH = 256


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def generate_initial_password() -> str:
    """A one-time password the admin hands over; easy to type, 16 characters."""
    alphabet = string.ascii_letters + string.digits
    alphabet = "".join(c for c in alphabet if c not in "0O1lI")
    return "".join(secrets.choice(alphabet) for _ in range(16))


def password_problem(password: str, username: str, min_length: int) -> str | None:
    """Return a plain-English problem with a new password, or None if it is fine."""
    if len(password) < min_length:
        return f"Your new password must be at least {min_length} characters long. Try a short sentence."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Your new password can be at most {MAX_PASSWORD_LENGTH} characters long."
    if username.lower() in password.lower():
        return "Your new password must not contain your username. Choose something else."
    return None
