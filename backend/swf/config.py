"""Deployment settings, read from environment variables (see .env.example).

Settings that describe *what the app is* (name, terms, modules...) live in `AppConfig` instead.
"""

import base64
from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "production"  # "production" | "development" | "test"
    log_level: str = "INFO"
    docs_enabled: bool = False

    database_url: str = "postgresql+psycopg://app:app@localhost:5432/app"

    # Key-encryption key (KEK) for the per-user vault: 32 random bytes, urlsafe base64.
    master_key: SecretStr

    # Host names the app answers to (comma-separated). Requests for any other Host are refused.
    allowed_hosts: str = "localhost,127.0.0.1"

    cookie_secure: bool = True
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    pending_login_minutes: int = 10

    lockout_threshold: int = 5
    lockout_minutes: int = 15
    password_min_length: int = 12

    # Per client address. Sign-in endpoints have their own, much lower limit.
    rate_limit_auth_per_minute: int = 10
    rate_limit_auth_per_hour: int = 60
    rate_limit_api_per_minute: int = 300

    max_request_bytes: int = 1_048_576  # 1 MiB

    # Passkeys (WebAuthn). The relying-party ID is the bare domain; the origin includes the scheme.
    webauthn_rp_id: str = "localhost"
    webauthn_origin: str = "http://localhost:5173"

    retention_job_enabled: bool = True
    retention_job_interval_hours: int = 24

    @field_validator("master_key")
    @classmethod
    def _check_master_key(cls, value: SecretStr) -> SecretStr:
        try:
            raw = base64.urlsafe_b64decode(value.get_secret_value())
        except ValueError as exc:  # binascii.Error is a ValueError
            raise ValueError("MASTER_KEY must be urlsafe base64") from exc
        if len(raw) != 32:
            raise ValueError("MASTER_KEY must decode to exactly 32 bytes")
        return value

    @property
    def master_key_bytes(self) -> bytes:
        return base64.urlsafe_b64decode(self.master_key.get_secret_value())

    @property
    def allowed_host_list(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
