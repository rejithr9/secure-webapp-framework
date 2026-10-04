"""Request dependencies: who is signed in, and which gates they have passed.

Gates, in order:
  1. a full session (password + authenticator code),
  2. the one-time initial password has been changed,
  3. the current terms have been accepted.
Every user-data endpoint requires all three (`ReadyUser`). Admin endpoints additionally
require the admin role (`AdminUser`). Apps protect their own routes with the same types.
"""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from swf.db import get_db
from swf.errors import AppError, not_signed_in
from swf.models import ROLE_ADMIN, STAGE_FULL, User, UserSession
from swf.security.sessions import load_session
from swf.services.signin import terms_accepted

DB = Annotated[Session, Depends(get_db)]


def optional_session(request: Request, db: DB) -> UserSession | None:
    return load_session(db, request)


def any_session(session: Annotated[UserSession | None, Depends(optional_session)]) -> UserSession:
    if session is None:
        raise not_signed_in()
    return session


def full_session(session: Annotated[UserSession, Depends(any_session)]) -> UserSession:
    if session.stage != STAGE_FULL:
        raise AppError(401, "second_step_required", "Finish signing in with the code from your authenticator app.")
    return session


def signed_in_user(session: Annotated[UserSession, Depends(full_session)]) -> User:
    return session.user


def ready_user(user: Annotated[User, Depends(signed_in_user)]) -> User:
    if user.must_change_password:
        raise AppError(
            403,
            "password_change_required",
            "Please replace your one-time password with your own password before you continue.",
        )
    if not terms_accepted(user):
        raise AppError(403, "terms_not_accepted", "Please read and accept the terms of use before you continue.")
    return user


def admin_user(user: Annotated[User, Depends(ready_user)]) -> User:
    if user.role != ROLE_ADMIN:
        raise AppError(403, "admin_only", "This page is for the administrator only.")
    return user


AnySession = Annotated[UserSession, Depends(any_session)]
FullSession = Annotated[UserSession, Depends(full_session)]
SignedInUser = Annotated[User, Depends(signed_in_user)]
ReadyUser = Annotated[User, Depends(ready_user)]
AdminUser = Annotated[User, Depends(admin_user)]
OptionalSession = Annotated[UserSession | None, Depends(optional_session)]
