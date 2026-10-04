"""Password hashing and the key vault."""

import uuid

import pytest
from cryptography.exceptions import InvalidTag

from swf.security import passwords
from swf.security.vault import UserVault, new_wrapped_dek


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = passwords.hash_password("a long enough password")
    assert hashed.startswith("$argon2id$")
    assert "a long enough password" not in hashed
    assert passwords.verify_password(hashed, "a long enough password")
    assert not passwords.verify_password(hashed, "a long enough passworD")


def test_same_password_hashes_differently() -> None:
    assert passwords.hash_password("same password here") != passwords.hash_password("same password here")


def test_verify_handles_missing_or_broken_hash() -> None:
    assert not passwords.verify_password(None, "anything")
    assert not passwords.verify_password("not-a-hash", "anything")


def test_password_rules() -> None:
    assert passwords.password_problem("short", "alice", 12) is not None
    assert passwords.password_problem("my alice password!", "alice", 12) is not None
    assert passwords.password_problem("x" * 300, "alice", 12) is not None
    assert passwords.password_problem("a perfectly fine one", "alice", 12) is None


def test_initial_password_is_random_and_long() -> None:
    a, b = passwords.generate_initial_password(), passwords.generate_initial_password()
    assert len(a) == 16 and a != b


def test_vault_round_trip() -> None:
    user_id = uuid.uuid4()
    vault = UserVault(user_id, new_wrapped_dek(user_id))
    nonce, ct = vault.encrypt(b"sk-or-secret-1234", "secret", "ai_service")
    assert b"sk-or-secret-1234" not in ct
    assert len(nonce) == 12
    assert vault.decrypt(nonce, ct, "secret", "ai_service") == b"sk-or-secret-1234"


def test_vault_ciphertext_is_bound_to_user_and_purpose() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    wrapped_a = new_wrapped_dek(a)
    vault_a = UserVault(a, wrapped_a)
    nonce, ct = vault_a.encrypt(b"key", "secret", "maps")

    with pytest.raises(InvalidTag):  # same ciphertext, different provider
        vault_a.decrypt(nonce, ct, "secret", "weather")
    with pytest.raises(InvalidTag):  # another user's key
        UserVault(b, new_wrapped_dek(b)).decrypt(nonce, ct, "secret", "maps")
    with pytest.raises(InvalidTag):  # a wrapped data key copied onto another user
        UserVault(b, wrapped_a)


def test_wrapped_data_keys_are_unique_per_user() -> None:
    user_id = uuid.uuid4()
    assert new_wrapped_dek(user_id) != new_wrapped_dek(user_id)


def test_seal_json_round_trip() -> None:
    user_id = uuid.uuid4()
    vault = UserVault(user_id, new_wrapped_dek(user_id))
    blob = vault.seal_json({"provider": "weather"}, "audit")
    assert b"weather" not in blob
    assert vault.open_json(blob, "audit") == {"provider": "weather"}
