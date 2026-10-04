# Security

This page explains what the framework protects against, how, and what remains the app's or the
operator's responsibility. Each control has automated tests (file names in brackets).

## Assets and threats

| Asset | Main threats |
| --- | --- |
| Accounts | Password guessing, credential stuffing, stolen passwords, phishing, stolen sessions |
| Users' data and API keys | Other users, the administrator, database leaks, backups |
| Integrity of actions | Cross-site request forgery, replayed codes, forged audit history |
| Availability | Request floods, oversized requests |

Out of scope: a fully compromised server (whoever controls the running app can read data it must
decrypt), the user's own device, and denial of service at network level (use your host's protection).

## Controls

### Authentication (`test_auth.py`, `test_recovery_passkeys.py`)

- **Passwords**: Argon2id (argon2-cffi defaults, rehash on parameter change). Minimum 12 characters
  (configurable), maximum 256, must not contain the username. One-time initial passwords
  (16 random characters) must be replaced at first sign-in.
- **Second factor is mandatory.** TOTP (RFC 6238, 30-second steps, ±1 step drift). A used code can
  never be used again (the last step is stored). The TOTP seed is encrypted with the user's key.
- **Passkeys (WebAuthn)**, if enabled: an alternative second step after the password. Challenges are
  random, single-use, bound to one session and expire after 5 minutes. The origin and relying-party
  ID are verified, which makes passkeys phishing-resistant. Sign counters are checked against clones.
  Adding a passkey requires the password and a fresh code.
- **Recovery codes**: 10 codes of ~50 bits, stored as SHA-256 hashes, each usable once. Using one is
  audited and the remaining count is shown. New codes require the password and a fresh code.
- **Lockout**: 5 wrong passwords, codes, recovery codes or passkey attempts (configurable) lock the
  account for 15 minutes and end all its sessions. The counter is reset only by a *complete*
  sign-in, so a known password can't be used to keep guessing codes.
- **No account enumeration**: unknown users, wrong passwords, locked and deactivated accounts all
  give the same response, and unknown users still cost one Argon2 verification.
- **Rate limits** per client address on all sign-in endpoints (10/minute, 60/hour) and on the
  whole API (300/minute), configurable. They work per process; run one back-end process.

### Sessions (`test_auth.py`)

- 256-bit random tokens; only their SHA-256 hash is stored.
- Cookies: `HttpOnly`, `Secure`, `SameSite=Strict`, path `/`.
- Idle timeout (30 min) and absolute timeout (12 h); pending sign-ins expire after 10 minutes.
- A new token on every stage change (password → second factor → full), so session fixation fails.
- Password change, reset, deactivation and lockout end the relevant sessions.
- Sensitive actions (password change, new recovery codes, adding a passkey, deleting the account)
  require the password and a fresh code again.

### Request forgery and browser security (`test_security.py`, `test_auth.py`)

- CSRF, three layers: `SameSite=Strict` cookies; refusing requests that the browser marks as
  cross-site (`Sec-Fetch-Site`) or that carry a foreign `Origin`; and a double-submit token
  (`X-CSRF-Token` header must equal the `swf_csrf` cookie), rotated with each new session.
  Sign-in itself is protected too (no login CSRF).
- Security headers on every API response: `Cache-Control: no-store`, `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a deny-all CSP, COOP/CORP,
  `Permissions-Policy`. The reverse proxy (Caddy) adds HSTS and the page CSP.
- Requests for unknown host names are refused (`ALLOWED_HOSTS`).
- Request bodies over 1 MiB are refused, with or without a `Content-Length` header.
- The front end never uses `dangerouslySetInnerHTML`; terms are rendered as React elements.

### Injection (`test_security.py`)

- All database access goes through SQLAlchemy with bound parameters; there is no string-built SQL
  (the one exception, `TRUNCATE` in test helpers, uses table names from the model metadata).
  Classic SQL injection payloads are tested in sign-in, stored fields, paths and query strings.
- Inputs are validated with Pydantic (types, lengths, enums); unknown fields are ignored.
- Static analysis in CI: ruff with flake8-bandit rules, bandit, CodeQL.

### Data protection and privacy (`test_crypto.py`, `test_admin.py`, `test_deletion.py`)

- **Envelope encryption**: `MASTER_KEY` (environment) wraps a random 256-bit key per user;
  user data is encrypted with AES-256-GCM using that key. Associated data binds every ciphertext
  to its owner and purpose, so ciphertexts can't be moved between users or fields.
- Encrypted per user: stored API keys, TOTP seeds, audit details, and any app fields that use
  `UserVault`. API keys are never returned; only the last 4 characters are shown.
- **The administrator cannot reach user data.** A test lists every route and fails if a new route
  isn't classified; admin routes return only account fields (username, role, status, dates).
- **Deletion**: users can delete their account with password + code; all their rows go (foreign
  keys cascade). Deactivated accounts are purged automatically after the retention period.
- **Retention includes backups**: `RetentionPolicy(max_total_days, backup_days)` caps the admin
  setting at `max_total_days - backup_days`, so data never outlives the promise in old backups.

### Audit (`test_terms_keys_audit.py`, `test_security.py`)

- Every sign-in, failure, lockout, 2FA, passkey, recovery-code, key, password and terms event is
  recorded per user (details encrypted). Users see only their own log.
- Admin and system actions go to a separate admin log.
- In PostgreSQL, database triggers make audit rows impossible to edit and admin-log rows impossible
  to edit or delete.

### Errors and information leakage (`test_security.py`, `test_no_secrets.py`)

- Every error is JSON with a stable code and a plain-English message. Unexpected errors return a
  generic message; details go only to the server log, without request bodies.
- No version numbers are exposed; the `Server` header is removed; API docs are off in production.
- Tests check that passwords, keys, TOTP seeds and session tokens never appear in logs or
  responses.

### Supply chain

- CI runs `pip-audit`, `npm audit` (high and above), bandit and CodeQL on every push and weekly.
- Dependabot keeps dependencies and GitHub Actions current. Actions are pinned to commit SHAs.
- Workflows run with read-only permissions; only the release job can write, and only from a tag
  whose build passed every check.

## Operator checklist

- [ ] Generate `MASTER_KEY` randomly and keep it in a password manager, apart from backups.
- [ ] Set `ALLOWED_HOSTS`, `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` to your real domain.
- [ ] Keep `COOKIE_SECURE=true` and serve only over HTTPS (Caddy does this automatically).
- [ ] Run a single back-end process (rate limits are per process).
- [ ] Set `backup_days` in your `RetentionPolicy` to your real backup history.
- [ ] Firewall: only 22, 80 and 443 open; SSH keys only; automatic security updates.
- [ ] Watch the GitHub security alerts for the framework and your app.
