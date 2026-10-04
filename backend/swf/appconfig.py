"""What an application is: name, terms, modules, policies. Passed to `create_app` in code.

Environment-specific values (database, keys, timeouts) live in `swf.config.Settings` instead.
"""

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from fastapi import APIRouter


@dataclass(frozen=True)
class SecretProvider:
    """A service whose API key each user can store in their own encrypted vault."""

    id: str
    name: str
    unlocks: str  # plain English: what adding this key switches on
    signup_url: str = ""


@dataclass(frozen=True)
class TermsConfig:
    """Terms every user must accept. Raising `version` makes everyone accept again."""

    version: str
    text: str  # Markdown subset: headings, numbered lists, paragraphs, **bold**

    @classmethod
    def from_file(cls, version: str, path: str | Path) -> "TermsConfig":
        return cls(version=version, text=Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class RetentionPolicy:
    """How long a deactivated account's data may exist, *including* in backups.

    The admin can choose how many days to keep a deactivated account in the live database,
    up to `max_total_days - backup_days`, so that live data plus the oldest backup never
    exceeds `max_total_days`.
    """

    max_total_days: int = 182
    backup_days: int = 0
    min_days: int = 1

    def __post_init__(self) -> None:
        if self.max_setting < self.min_days:
            raise ValueError("backup_days leaves no room for live retention; lower it or raise max_total_days")

    @property
    def max_setting(self) -> int:
        return self.max_total_days - self.backup_days

    @property
    def default_days(self) -> int:
        return self.max_setting


@dataclass(frozen=True)
class Module:
    """A self-contained feature an app plugs into the framework.

    - `routers`: FastAPI routers. Protect user routes with `swf.deps.ReadyUser`, admin
      routes with `swf.deps.AdminUser`.
    - Database tables subclass `swf.db.Base`. Every user-owned table must reference
      `users.id` with `ondelete="CASCADE"`, so account deletion and the retention purge
      remove it automatically.
    - `audit_labels`: plain-English labels for audit event types the module records.
    - `background_jobs`: coroutines started with the app (each should loop forever).
    """

    name: str
    routers: Sequence[APIRouter] = ()
    audit_labels: Mapping[str, str] = field(default_factory=dict)
    background_jobs: Sequence[Callable[[], Awaitable[None]]] = ()


@dataclass(frozen=True)
class AppConfig:
    name: str
    max_users: int = 10
    terms: TermsConfig | None = None  # None: no terms gate
    secret_providers: Sequence[SecretProvider] = ()
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    # "second_factor": after the password, a passkey can be used instead of an authenticator code.
    passkeys: Literal["off", "second_factor"] = "second_factor"
    recovery_codes: bool = True
    modules: Sequence[Module] = ()

    def __post_init__(self) -> None:
        ids = [p.id for p in self.secret_providers]
        if len(ids) != len(set(ids)):
            raise ValueError("secret provider ids must be unique")
        names = [m.name for m in self.modules]
        if len(names) != len(set(names)):
            raise ValueError("module names must be unique")
        if self.max_users < 1:
            raise ValueError("max_users must be at least 1")


_current: AppConfig | None = None


def set_app_config(config: AppConfig) -> None:
    global _current
    _current = config


def get_app_config() -> AppConfig:
    if _current is None:
        raise RuntimeError("No AppConfig set: call swf.create_app(config) first")
    return _current
