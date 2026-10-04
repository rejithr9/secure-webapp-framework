# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, minor versions may change the API.

## [0.1.0] - 2026-10-04

First release: a reusable, security-first framework for private multi-user web apps.

### Back end (`secure-webapp-framework`, Python package `swf`)

- `AppConfig` and `create_app`: describe an app (name, user limit, terms, key providers, retention,
  passkeys, recovery codes) and plug in feature modules with their own routes, tables and audit labels.
- Accounts created by admins with one-time passwords; roles `user` and `admin`.
- Sign-in with Argon2id passwords and mandatory TOTP 2FA (replay-protected); passkeys (WebAuthn)
  as an alternative second step; 10 single-use recovery codes; lockout.
- Server-side sessions with hashed tokens, strict cookies, idle and absolute timeouts.
- Three-layer CSRF defence, security headers, trusted hosts, request-size limit, rate limits.
- Envelope encryption (per-user AES-256-GCM keys wrapped by a master key) and a per-user key vault.
- Encrypted per-user audit trail, separate admin log, append-only in PostgreSQL.
- Admin area for accounts and settings only; no access to user data.
- Self-service account deletion; retention purge whose limit includes backup age.
- Alembic migrations with separate framework and app branches; CLI (`migrate`, `make-migration`,
  `create-admin`, `purge-retention`, `generate-master-key`).
- `swf.testing`: fixtures helpers and a software passkey authenticator for app test suites.

### Front end (`@swf/web`)

- `<SwfApp>`: sign-in, 2FA setup, passkeys, recovery codes, password change, terms, account,
  keys, activity and admin screens, plus the app's own pages in a shared shell.
- API helpers with CSRF handling and plain-English errors; light and dark themes.

### Project

- Example app (`examples/notes`), deployment templates (Docker Compose, Caddy, encrypted backups,
  Hetzner guide), security documentation, CI with tests on SQLite and PostgreSQL, ruff, bandit,
  pip-audit, npm audit and CodeQL, and a release workflow.

[0.1.0]: https://github.com/rejithr9/secure-webapp-framework/releases/tag/v0.1.0
