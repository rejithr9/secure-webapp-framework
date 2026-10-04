"""Endpoints that need no sign-in."""

from fastapi import APIRouter

from swf.appconfig import get_app_config
from swf.config import get_settings
from swf.errors import AppError

router = APIRouter(prefix="/api", tags=["public"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/config")
def public_config() -> dict:
    """What the front end needs to know before sign-in. No version numbers (they help attackers)."""
    config = get_app_config()
    return {
        "app_name": config.name,
        "terms_enabled": config.terms is not None,
        "passkeys": config.passkeys,
        "recovery_codes": config.recovery_codes,
        "keys_enabled": bool(config.secret_providers),
        "password_min_length": get_settings().password_min_length,
    }


@router.get("/terms")
def get_terms() -> dict:
    terms = get_app_config().terms
    if terms is None:
        raise AppError(404, "no_terms", "This app has no terms to accept.")
    return {"version": terms.version, "text": terms.text}
