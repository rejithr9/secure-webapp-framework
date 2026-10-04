"""Passkeys (WebAuthn) as a second factor, using py_webauthn.

Challenges are random, single-use, bound to one session and expire after 5 minutes.
"""

import json
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from swf import clock
from swf.appconfig import get_app_config
from swf.config import get_settings
from swf.models import Passkey, User, UserSession

CHALLENGE_MINUTES = 5
PURPOSE_REGISTER = "register"
PURPOSE_SIGN_IN = "sign_in"


class PasskeyError(Exception):
    pass


def _descriptors(user: User) -> list[PublicKeyCredentialDescriptor]:
    out = []
    for pk in user.passkeys:
        transports = []
        for t in pk.transports or []:
            try:
                transports.append(AuthenticatorTransport(t))
            except ValueError:
                continue
        out.append(PublicKeyCredentialDescriptor(id=pk.credential_id, transports=transports or None))
    return out


def _remember(session: UserSession, challenge: bytes, purpose: str) -> None:
    session.challenge = challenge
    session.challenge_purpose = purpose
    session.challenge_expires_at = clock.utcnow() + timedelta(minutes=CHALLENGE_MINUTES)


def _take_challenge(session: UserSession, purpose: str) -> bytes:
    """Return the session's pending challenge for `purpose` and clear it (single use)."""
    challenge, stored_purpose, expires = session.challenge, session.challenge_purpose, session.challenge_expires_at
    session.challenge = session.challenge_purpose = session.challenge_expires_at = None
    if challenge is None or stored_purpose != purpose or expires is None or clock.utcnow() >= expires:
        raise PasskeyError("challenge missing or expired")
    return challenge


def registration_options(session: UserSession, user: User) -> dict[str, Any]:
    settings = get_settings()
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=get_app_config().name,
        user_id=user.id.bytes,
        user_name=user.username,
        exclude_credentials=_descriptors(user),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    _remember(session, options.challenge, PURPOSE_REGISTER)
    return json.loads(options_to_json(options))


def register(db: Session, session: UserSession, user: User, credential: dict[str, Any], name: str) -> Passkey:
    settings = get_settings()
    challenge = _take_challenge(session, PURPOSE_REGISTER)
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError("registration not verified") from exc
    if db.query(Passkey).filter(Passkey.credential_id == verified.credential_id).first() is not None:
        raise PasskeyError("credential already registered")
    transports = credential.get("response", {}).get("transports")
    passkey = Passkey(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=[t for t in transports if isinstance(t, str)][:8] if isinstance(transports, list) else None,
        name=name,
        created_at=clock.utcnow(),
    )
    user.passkeys.append(passkey)
    return passkey


def authentication_options(session: UserSession, user: User) -> dict[str, Any]:
    options = generate_authentication_options(
        rp_id=get_settings().webauthn_rp_id,
        allow_credentials=_descriptors(user),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    _remember(session, options.challenge, PURPOSE_SIGN_IN)
    return json.loads(options_to_json(options))


def authenticate(session: UserSession, user: User, credential: dict[str, Any]) -> Passkey:
    settings = get_settings()
    challenge = _take_challenge(session, PURPOSE_SIGN_IN)
    try:
        raw_id = base64url_to_bytes(str(credential["rawId"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise PasskeyError("malformed credential") from exc
    passkey = next((pk for pk in user.passkeys if pk.credential_id == raw_id), None)
    if passkey is None:
        raise PasskeyError("unknown credential")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError("assertion not verified") from exc
    passkey.sign_count = verified.new_sign_count
    passkey.last_used_at = clock.utcnow()
    return passkey
