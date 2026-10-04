"""TOTP (authenticator app) helpers with replay protection."""

import base64
import hmac
from datetime import datetime
from urllib.parse import unquote

import pyotp
import segno

STEP_SECONDS = 30
VALID_WINDOW = 1  # accept the previous and next 30-second code too (clock drift)


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def qr_svg_data_uri(uri: str) -> str:
    """A standalone SVG (with xmlns) as a data URI, usable as an <img> source."""
    svg = segno.make(uri, error="m").svg_data_uri(scale=5, dark="#000000", light="#ffffff", xmldecl=False)
    payload = svg.split(",", 1)[1]
    return "data:image/svg+xml;base64," + base64.b64encode(unquote(payload).encode()).decode()


def matching_step(secret: str, code: str, now: datetime, last_step: int | None) -> int | None:
    """Return the time step the code belongs to, or None if it is wrong or already used."""
    code = code.strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int(now.timestamp()) // STEP_SECONDS
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if hmac.compare_digest(totp.at(step * STEP_SECONDS), code):
            if last_step is not None and step <= last_step:
                return None  # replay of a code that was already used
            return step
    return None
