"""HTTP hardening middleware: security headers, request size limit, API rate limit."""

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from swf.config import get_settings
from swf.security.ratelimit import Limit, limiter

# Applied to every API response. The reverse proxy adds HSTS and the page CSP for the front end.
API_SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),
    (b"pragma", b"no-cache"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
]


async def _send_json(send: Send, status: int, body: dict, extra_headers: list[tuple[bytes, bytes]] = ()) -> None:  # type: ignore[assignment]
    payload = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers + list(extra_headers)})
    await send({"type": "http.response.body", "body": payload})


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api"):
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + [
                    (k, v) for k, v in API_SECURITY_HEADERS if k not in existing
                ]
                message["headers"] = [(k, v) for k, v in message["headers"] if k.lower() != b"server"]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Refuse request bodies larger than MAX_REQUEST_BYTES, whether or not Content-Length is sent."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = get_settings().max_request_bytes
        too_large = {
            "code": "request_too_large",
            "message": "What you sent is too large. Try something smaller.",
        }
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        await _send_json(send, 413, too_large)
                        return
                except ValueError:
                    await _send_json(send, 400, {"code": "bad_request", "message": "Invalid request."})
                    return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _send_json(send, 413, too_large)


class _BodyTooLarge(Exception):
    pass


class ApiRateLimitMiddleware:
    """A generous per-address ceiling on all API calls, against floods and scraping."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        key = client[0] if client else "unknown"
        retry = limiter.hit("api", key, [Limit(get_settings().rate_limit_api_per_minute, 60)])
        if retry is not None:
            await _send_json(
                send,
                429,
                {"code": "too_many_requests", "message": "Too many requests. Please wait a minute and try again."},
                [(b"retry-after", str(retry).encode())],
            )
            return
        await self.app(scope, receive, send)
