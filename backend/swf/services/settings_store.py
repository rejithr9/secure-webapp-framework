"""Admin-adjustable settings stored in the database."""

from typing import Any

from sqlalchemy.orm import Session

from swf import clock
from swf.appconfig import get_app_config
from swf.models import AppSetting

RETENTION_DAYS = "retention_days"


def get(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(AppSetting, key)
    return row.value if row is not None else default


def put(db: Session, key: str, value: Any) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value, updated_at=clock.utcnow()))
    else:
        row.value = value
        row.updated_at = clock.utcnow()


def retention_days(db: Session) -> int:
    """Days a deactivated account is kept, clamped to the app's retention policy.

    Clamping also applies if the policy was tightened after the admin chose a value.
    """
    policy = get_app_config().retention
    value = int(get(db, RETENTION_DAYS, policy.default_days))
    return max(policy.min_days, min(value, policy.max_setting))
