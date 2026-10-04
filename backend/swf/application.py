"""`create_app`: turns an `AppConfig` into a hardened FastAPI application."""

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from swf import retention
from swf.appconfig import AppConfig, set_app_config
from swf.config import get_settings
from swf.errors import (
    AppError,
    app_error_handler,
    http_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from swf.routers import admin, auth, keys, me, public
from swf.security.middleware import ApiRateLimitMiddleware, BodySizeLimitMiddleware, SecurityHeadersMiddleware
from swf.security.sessions import CSRFMiddleware

FRAMEWORK_PREFIXES = ("/api/auth", "/api/me", "/api/keys", "/api/admin", "/api/health", "/api/config", "/api/terms")


def create_app(config: AppConfig) -> FastAPI:
    set_app_config(config)
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        jobs = []
        if settings.retention_job_enabled:
            jobs.append(asyncio.create_task(retention.run_forever()))
        for module in config.modules:
            jobs.extend(asyncio.create_task(job()) for job in module.background_jobs)
        yield
        for job in jobs:
            job.cancel()

    docs = settings.docs_enabled
    app = FastAPI(
        title=config.name,
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )

    # Starlette runs the last-added middleware first. Effective order, outermost first:
    # trusted host -> security headers -> body size -> API rate limit -> CSRF -> routes.
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(ApiRateLimitMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)

    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    for module in (public, auth, me, keys, admin):
        app.include_router(module.router)
    for module in config.modules:
        for router in module.routers:
            for route in router.routes:
                path = getattr(route, "path", "")
                if path.startswith(FRAMEWORK_PREFIXES) or not path.startswith("/api/"):
                    raise ValueError(
                        f"Module '{module.name}' route {path!r} must live under /api/ and not "
                        f"under a framework prefix {FRAMEWORK_PREFIXES}"
                    )
            app.include_router(router)
    return app
