"""Server-side sessions and CSRF protection.

The browser holds a random session token in an httpOnly, Secure, SameSite=Strict cookie.
The database stores only the SHA-256 hash of that token.

CSRF defence has three layers for every state-changing API request:
  1. SameSite=Strict cookies (browsers don't send them on cross-site requests),
  2. Fetch-metadata / Origin checks: cross-site requests are refused outright,
  3. the double-submit token: a random token in a readable cookie must be echoed in the
     X-CSRF-Token header. A new token is issued whenever a session is created or upgraded.
"""

import hashlib
import hmac
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from swf import clock
from swf.config import get_settings
from swf.models import STAGE_FULL, User, UserSession

SESSION_COOKIE = "swf_session"
CSRF_COOKIE = "swf_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, response: Response, user: User, stage: str) -> UserSession:
    """Start a new session for `user` (replacing any token the browser had) and set cookies."""
    settings = get_settings()
    now = clock.utcnow()
    lifetime = (
        timedelta(hours=settings.session_absolute_hours)
        if stage == STAGE_FULL
        else timedelta(minutes=settings.pending_login_minutes)
    )
    token = secrets.token_urlsafe(32)
    record = UserSession(
        user_id=user.id,
        token_hash=hash_token(token),
        stage=stage,
        created_at=now,
        last_seen_at=now,
        expires_at=now + lifetime,
    )
    db.add(record)
    _set_cookie(response, SESSION_COOKIE, token, http_only=True)
    issue_csrf_cookie(response)
    return record


def load_session(db: Session, request: Request) -> UserSession | None:
    """Return the live session for this request, deleting it if it has expired."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    record = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if record is None:
        return None
    settings = get_settings()
    now = clock.utcnow()
    idle_limit = record.last_seen_at + timedelta(minutes=settings.session_idle_minutes)
    if now >= record.expires_at or now >= idle_limit or record.user.deactivated_at is not None:
        db.delete(record)
        db.commit()
        return None
    record.last_seen_at = now
    db.commit()
    return record


def end_session(db: Session, request: Request, response: Response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == hash_token(token)))
        db.commit()
    clear_cookies(response)


def revoke_all_sessions(db: Session, user_id, except_id=None) -> None:  # type: ignore[no-untyped-def]
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if except_id is not None:
        stmt = stmt.where(UserSession.id != except_id)
    db.execute(stmt)


def clear_cookies(response: Response) -> None:
    secure = get_settings().cookie_secure
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="strict")
    issue_csrf_cookie(response)


def issue_csrf_cookie(response: Response) -> None:
    _set_cookie(response, CSRF_COOKIE, secrets.token_urlsafe(32), http_only=False)


def _set_cookie(response: Response, name: str, value: str, http_only: bool) -> None:
    response.set_cookie(
        name,
        value,
        path="/",
        secure=get_settings().cookie_secure,
        httponly=http_only,
        samesite="strict",
    )


def _csrf_failed() -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "code": "csrf_failed",
            "message": "Your browser sent an unexpected request. Reload the page and try again.",
        },
    )


def is_cross_site(request: Request) -> bool:
    """True if the browser tells us the request comes from another site."""
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site not in ("same-origin", "none"):
        return True
    origin = request.headers.get("origin")
    if origin is not None:
        if origin == "null":
            return True
        # Compare with the configured host names, not the Host header: proxies may rewrite Host.
        hostname = (urlsplit(origin).hostname or "").lower()
        allowed = {h.lower() for h in get_settings().allowed_host_list}
        if "*" not in allowed and hostname not in allowed:
            return True
    return False


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject cross-site or token-less state-changing API requests."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):  # type: ignore[override]
        if request.method not in SAFE_METHODS and request.url.path.startswith("/api/"):
            if is_cross_site(request):
                return _csrf_failed()
            cookie = request.cookies.get(CSRF_COOKIE, "")
            header = request.headers.get(CSRF_HEADER, "")
            if not cookie or not header or not hmac.compare_digest(cookie, header):
                return _csrf_failed()
        response = await call_next(request)
        if CSRF_COOKIE not in request.cookies and "set-cookie" not in response.headers:
            issue_csrf_cookie(response)
        return response
