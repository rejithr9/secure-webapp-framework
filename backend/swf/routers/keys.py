"""The signed-in user's own API keys ("My keys"). Keys are never returned in full."""

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

from swf.appconfig import get_app_config
from swf.deps import DB, ReadyUser
from swf.errors import AppError
from swf.services import audit, keys

router = APIRouter(prefix="/api/keys", tags=["keys"])


class KeyIn(BaseModel):
    secret: str = Field(min_length=8, max_length=1000)
    label: str | None = Field(default=None, max_length=64)


def _provider_or_404(provider: str) -> None:
    if keys.provider(provider) is None:
        raise AppError(404, "unknown_provider", "We don't know that provider. Pick one from the list.")


@router.get("")
def list_keys(user: ReadyUser) -> dict:
    stored = {row.provider: row for row in user.secrets}
    items = []
    for provider in get_app_config().secret_providers:
        row = stored.get(provider.id)
        items.append(
            {
                "provider": provider.id,
                "name": provider.name,
                "unlocks": provider.unlocks,
                "signup_url": provider.signup_url,
                "has_key": row is not None,
                "masked": keys.masked(user, row) if row else None,
                "label": row.label if row else None,
                "added_at": row.created_at.isoformat() if row else None,
                "last_used_at": row.last_used_at.isoformat() if row and row.last_used_at else None,
            }
        )
    return {"items": items}


@router.put("/{provider}")
def put_key(provider: str, body: KeyIn, user: ReadyUser, db: DB) -> dict:
    _provider_or_404(provider)
    secret = body.secret.strip()
    if len(secret) < 8 or any(c.isspace() for c in secret):
        raise AppError(422, "invalid_key", "That doesn't look like a key. Copy it again from the provider's website.")
    label = body.label.strip() if body.label and body.label.strip() else None
    replaced = keys.store(db, user, provider, secret, label)
    audit.record(db, user, audit.KEY_REPLACED if replaced else audit.KEY_ADDED, {"provider": provider})
    db.commit()
    return {"provider": provider, "masked": "••••" + secret[-4:], "replaced": replaced}


@router.delete("/{provider}", status_code=204)
def delete_key(provider: str, user: ReadyUser, db: DB) -> Response:
    _provider_or_404(provider)
    row = keys.find(db, user, provider)
    if row is None:
        raise AppError(404, "no_key", "You have no key stored for this provider.")
    db.delete(row)
    audit.record(db, user, audit.KEY_REMOVED, {"provider": provider})
    db.commit()
    return Response(status_code=204)
