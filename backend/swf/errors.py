"""Errors with a stable code and a plain-English message that says what to do next."""

import logging

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)


class AppError(Exception):
    def __init__(self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers


SIGN_IN_FAILED = (
    "We couldn't sign you in. Check your username, password and code, and try again. "
    "After several wrong tries the account is locked for a short while, so wait a bit "
    "before trying again, or ask the administrator to reset your sign-in."
)


def not_signed_in() -> AppError:
    return AppError(401, "not_signed_in", "You are not signed in, or your session has ended. Please sign in again.")


def sign_in_failed() -> AppError:
    return AppError(401, "sign_in_failed", SIGN_IN_FAILED)


def wrong_code() -> AppError:
    return AppError(
        401,
        "wrong_code",
        "That code didn't work. Enter the current 6-digit code from your authenticator app. "
        "If you just used a code, wait for the next one.",
    )


async def app_error_handler(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):  # pragma: no cover - registered for AppError only
        raise exc
    return JSONResponse(
        status_code=exc.status_code, content={"code": exc.code, "message": exc.message}, headers=exc.headers
    )


_HTTP_MESSAGES = {
    404: ("not_found", "We couldn't find that. Check the address, or go back to the start page."),
    405: ("method_not_allowed", "That action isn't possible here."),
}


async def http_error_handler(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover
        raise exc
    code, message = _HTTP_MESSAGES.get(exc.status_code, ("error", "Something went wrong. Please try again."))
    return JSONResponse(status_code=exc.status_code, content={"code": code, "message": message})


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Log the type and place, never request bodies (they may hold passwords or keys).
    log.error("Unhandled %s on %s %s", type(exc).__name__, request.method, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"code": "server_error", "message": "Something went wrong on our side. Please try again in a minute."},
    )


async def validation_error_handler(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        raise exc
    fields = sorted({str(err["loc"][-1]) for err in exc.errors() if err.get("loc")})
    hint = f" Please check: {', '.join(fields)}." if fields else ""
    return JSONResponse(
        status_code=422,
        content={"code": "invalid_input", "message": "Some of the information you sent isn't valid." + hint},
    )
