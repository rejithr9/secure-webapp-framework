"""No password, key, code secret or session token in logs or responses."""

import logging

from swf.security.sessions import SESSION_COOKIE
from tests.conftest import NEW_PASSWORD, create_account, new_client, next_code


def test_secrets_never_logged_or_echoed(engine, clock, db, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    key = "sk-or-v1-supersecretvalue-ABCD"
    client = new_client()
    responses = []

    initial = create_account(db, "carol")
    responses.append(client.post("/api/auth/login", json={"username": "carol", "password": initial}))
    setup = client.get("/api/auth/totp/setup")
    secret = setup.json()["secret"]
    responses.append(client.post("/api/auth/totp/enable", json={"code": next_code(secret, clock)}))
    token = client.cookies.get(SESSION_COOKIE)
    responses.append(
        client.post(
            "/api/auth/password",
            json={"current_password": initial, "new_password": NEW_PASSWORD, "totp_code": next_code(secret, clock)},
        )
    )
    responses.append(client.post("/api/me/terms/accept", json={"version": "1"}))
    responses.append(client.put("/api/keys/ai_service", json={"secret": key}))
    responses.append(client.get("/api/keys"))
    responses.append(client.get("/api/me/audit"))
    responses.append(client.get("/api/me"))
    responses.append(client.post("/api/auth/login", json={"username": "carol", "password": "wrong password!"}))

    logged = caplog.text
    for value in (initial, NEW_PASSWORD, key, secret, token):
        assert value not in logged
    for r in responses:
        for value in (initial, NEW_PASSWORD, key, secret, token):
            assert value not in r.text, r.request.url
    # The session token is only ever sent in a Set-Cookie header, never in a body.
    assert all(token not in r.text for r in responses)
