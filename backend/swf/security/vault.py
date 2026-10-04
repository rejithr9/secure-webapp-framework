"""Envelope encryption for per-user data.

- The key-encryption key (KEK) comes from the MASTER_KEY environment variable.
- Each user has a random 256-bit data key (DEK), stored wrapped (encrypted) by the KEK.
- User data is encrypted with the user's DEK using AES-256-GCM.
- Every ciphertext is bound to its owner and purpose via associated data (AAD),
  so a ciphertext copied to another user or column fails to decrypt.
"""

import json
import os
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from swf.config import get_settings

NONCE_BYTES = 12


def _aad(purpose: str, user_id: uuid.UUID, extra: str = "") -> bytes:
    return f"{purpose}:{user_id}:{extra}".encode()


def _kek() -> AESGCM:
    return AESGCM(get_settings().master_key_bytes)


def encrypt_raw(key: AESGCM, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_BYTES)
    return nonce, key.encrypt(nonce, plaintext, aad)


def new_wrapped_dek(user_id: uuid.UUID) -> bytes:
    """Create a fresh data key for a user and return it wrapped by the KEK."""
    dek = AESGCM.generate_key(bit_length=256)
    nonce, ct = encrypt_raw(_kek(), dek, _aad("dek", user_id))
    return nonce + ct


def _user_key(user_id: uuid.UUID, dek_wrapped: bytes) -> AESGCM:
    nonce, ct = dek_wrapped[:NONCE_BYTES], dek_wrapped[NONCE_BYTES:]
    return AESGCM(_kek().decrypt(nonce, ct, _aad("dek", user_id)))


class UserVault:
    """Encrypt and decrypt data for one user."""

    def __init__(self, user_id: uuid.UUID, dek_wrapped: bytes) -> None:
        self.user_id = user_id
        self._key = _user_key(user_id, dek_wrapped)

    @classmethod
    def for_user(cls, user: Any) -> "UserVault":
        return cls(user.id, user.dek_wrapped)

    def encrypt(self, plaintext: bytes, purpose: str, extra: str = "") -> tuple[bytes, bytes]:
        return encrypt_raw(self._key, plaintext, _aad(purpose, self.user_id, extra))

    def decrypt(self, nonce: bytes, ciphertext: bytes, purpose: str, extra: str = "") -> bytes:
        return self._key.decrypt(nonce, ciphertext, _aad(purpose, self.user_id, extra))

    # Single-blob helpers (nonce || ciphertext) for columns without a separate nonce.
    def seal(self, plaintext: bytes, purpose: str, extra: str = "") -> bytes:
        nonce, ct = self.encrypt(plaintext, purpose, extra)
        return nonce + ct

    def open(self, blob: bytes, purpose: str, extra: str = "") -> bytes:
        return self.decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], purpose, extra)

    def seal_json(self, value: Any, purpose: str) -> bytes:
        return self.seal(json.dumps(value, separators=(",", ":")).encode(), purpose)

    def open_json(self, blob: bytes, purpose: str) -> Any:
        return json.loads(self.open(blob, purpose))
