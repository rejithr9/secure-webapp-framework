# Secure Web App Framework

A reusable, security-first starting point for **private multi-user web apps**: a FastAPI back end
(`swf`) and a React front end (`@swf/web`). You describe your app in a few lines and add your own
pages and API; sign-in, two-factor authentication, passkeys, encryption, auditing, account
administration and data retention are already done and tested.

## What you get

| Area | Built in |
| --- | --- |
| Accounts | Admin-created accounts with one-time passwords (no self sign-up), configurable user limit, roles `user`/`admin` |
| Sign-in | Argon2id passwords · mandatory authenticator-app 2FA (TOTP, replay-protected) · **passkeys** (WebAuthn) as an alternative second step · 10 single-use **recovery codes** · lockout after repeated failures |
| Sessions | Server-side, random tokens stored only as hashes · httpOnly + Secure + SameSite=Strict cookies · idle and absolute timeouts · new token on every privilege change |
| Web security | Three-layer CSRF defence (SameSite, fetch-metadata/Origin checks, double-submit token) · strict security headers · trusted-host check · request-size limit · per-address rate limits · SQL only through bound parameters · no stack traces or versions in responses |
| Data protection | Envelope encryption: a master key wraps a per-user AES-256-GCM key; secrets, 2FA seeds, audit details and your own fields are encrypted per user and bound to their owner |
| Privacy | Admins manage accounts and settings but get **no** endpoint to any user's data · users can delete their account and all data · automatic deletion of deactivated accounts, with retention that includes backup age |
| Audit | Encrypted per-user activity log (users see only their own) · separate admin log · append-only in PostgreSQL |
| Terms | Optional terms every user must accept; raising the version asks everyone again |
| Key vault | Users store their own API keys for outside services; only the last 4 characters are ever shown |
| Front end | Complete UI for all of the above, light/dark theme, plain-English messages that say what to do next |
| Operations | Alembic migrations (framework + app branches), CLI, Docker Compose + Caddy (automatic HTTPS), encrypted backups, Hetzner guide |
| Quality | About 120 automated tests (SQLite and PostgreSQL) · CI with ruff, bandit, pip-audit, npm audit, CodeQL · releases only from passing builds |

See [docs/security.md](docs/security.md) for the threat model and every control in detail.

## Build an app in five steps

```python
# backend: myapp/main.py
from swf import AppConfig, Module, RetentionPolicy, TermsConfig, create_app
from myapp import api   # your FastAPI router, protected with swf.deps.ReadyUser

CONFIG = AppConfig(
    name="My App",
    max_users=10,
    terms=TermsConfig.from_file("1", "terms.md"),
    retention=RetentionPolicy(max_total_days=182, backup_days=30),
    modules=[Module(name="myapp", routers=[api.router])],
)
app = create_app(CONFIG)
```

```tsx
// frontend: src/main.tsx
import { SwfApp } from "@swf/web";
import "@swf/web/styles.css";

createRoot(root).render(
  <SwfApp config={{ home: <Dashboard />, nav: [{ path: "/projects", label: "Projects", element: <Projects /> }] }} />,
);
```

The full walk-through is in [docs/building-an-app.md](docs/building-an-app.md), and
[examples/notes](examples/notes) is a complete working app (encrypted private notes) with tests.

## Install a release

```bash
pip install "secure-webapp-framework @ https://github.com/rejithr9/secure-webapp-framework/releases/download/v0.1.0/secure_webapp_framework-0.1.0-py3-none-any.whl"
npm install https://github.com/rejithr9/secure-webapp-framework/releases/download/v0.1.0/swf-web-0.1.0.tgz
```

## Repository layout

```
backend/     swf: the Python package (FastAPI, SQLAlchemy, Alembic) and its tests
frontend/    @swf/web: the React library
examples/    notes: a complete example app (back end, front end, tests)
deploy/      Docker Compose, Caddyfile, backup script and Hetzner guide (templates for your app)
docs/        building an app, security
```

## Developing the framework

```bash
cd backend && python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"   # macOS/Linux: .venv/bin/python
.venv/Scripts/python -m pytest          # set TEST_DATABASE_URL=postgresql+psycopg://... to run against PostgreSQL
.venv/Scripts/ruff check . && .venv/Scripts/bandit -r swf -c pyproject.toml -ll

cd ../frontend && npm ci && npm run build
```

## Licence

MIT. See [LICENSE](LICENSE). Report security problems privately as described in [SECURITY.md](SECURITY.md).
