# Building an app on the framework

This guide builds an app step by step. [examples/notes](../examples/notes) is the finished result
of exactly these steps.

## 1. Project layout

```
myapp/
  backend/
    pyproject.toml          depends on secure-webapp-framework
    myapp/
      main.py               AppConfig + create_app
      models.py             your tables
      api.py                your routes
      migrations/           your Alembic branch (generated)
      cli.py                server commands
      terms.md              optional
    tests/
  frontend/
    package.json            depends on @swf/web, react, react-dom, react-router-dom
    src/main.tsx            <SwfApp config={...} />
  deploy/                   copied from the framework's deploy/ folder
```

## 2. Describe the app (`AppConfig`)

| Field | Meaning | Default |
| --- | --- | --- |
| `name` | Shown in the UI, the authenticator app and passkey prompts | required |
| `max_users` | Hard limit on accounts | 10 |
| `terms` | `TermsConfig(version, text)`; `None` turns the terms step off | `None` |
| `secret_providers` | Outside services whose API keys users can store (`SecretProvider(id, name, unlocks, signup_url)`); empty hides "My keys" | `()` |
| `retention` | `RetentionPolicy(max_total_days, backup_days)`: the admin may keep deactivated accounts for at most `max_total_days - backup_days` days | 182 / 0 |
| `passkeys` | `"second_factor"`: a passkey can replace the code after the password. `"off"` disables passkeys | `"second_factor"` |
| `recovery_codes` | Offer 10 single-use backup codes | `True` |
| `modules` | Your features (`Module(name, routers, audit_labels, background_jobs)`) | `()` |

Deployment-specific values (database, master key, timeouts, rate limits, allowed hosts, passkey
domain) come from environment variables. See [backend/.env.example](../backend/.env.example).

## 3. Add tables

```python
from sqlalchemy import ForeignKey, LargeBinary, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from swf.db import Base, UTCDateTime

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name_enc: Mapped[bytes] = mapped_column(LargeBinary)
```

Rules that keep the framework's guarantees intact:

1. **Every user-owned table references `users.id` with `ondelete="CASCADE"`.** Account deletion and
   the retention purge then remove the rows automatically.
2. **Encrypt personal content** with the owner's key:
   `UserVault.for_user(user).seal(data, "purpose", str(row_id))` and `.open(...)`. The purpose and
   row id bind the ciphertext to its place, so it can't be copied elsewhere.
3. Use `swf.clock.utcnow()` for timestamps (tests can move time) and `UTCDateTime` columns.

Generate the migration: `python -m myapp.cli make-migration -m "projects table"`. The first run
creates your app's own Alembic branch, which depends on the framework's.

## 4. Add routes

```python
from fastapi import APIRouter
from swf.deps import DB, ReadyUser, AdminUser

router = APIRouter(prefix="/api/projects")

@router.get("")
def list_projects(user: ReadyUser, db: DB) -> dict:
    rows = db.scalars(select(Project).where(Project.user_id == user.id)).all()   # always filter by the user
    ...
```

- `ReadyUser`: signed in with both factors, own password set, current terms accepted. Use it for every user route.
- `AdminUser`: as above, plus the admin role. **Never** give admins routes to user content.
- Raise `swf.errors.AppError(status, code, "Plain message that says what to do next.")` for errors.
- Record important actions with `swf.services.audit.record(db, user, "project_created", {...})`, and
  give the event a label through `Module(audit_labels={"project_created": "Project created"})`.
  Never put secrets into audit details.
- Routes must live under `/api/` and not under a framework prefix (`/api/auth`, `/api/me`,
  `/api/keys`, `/api/admin`, ...); `create_app` refuses them otherwise.
- A user's stored API key for server-side work: `swf.services.keys.use(db, user, "provider_id")`.

## 5. Front end

```tsx
<SwfApp
  config={{
    home: <Dashboard />,
    homeLabel: "Dashboard",
    nav: [{ path: "/projects", label: "Projects", element: <Projects /> }],
    shellExtras: <HelpButton />,      // e.g. a floating assistant
    logoSrc: "/logo.svg",
  }}
/>
```

Inside your pages, use `get`, `post`, `put` and `del` from `@swf/web`: they send the CSRF header,
show the sign-in page when a session ends, and turn errors into plain-English messages
(`errorMessage(err)`). UI helpers: `PageHeader`, `Card`, `Alert`, `Field`, `useAuth()`.

## 6. Test

```python
# tests/conftest.py
from swf.testing import setup_test_env
setup_test_env()
from myapp.main import app
from swf.testing import FakeClock, make_sqlite_engine, onboard
```

`onboard(app, db, clock, "alice")` gives you a fully signed-in user with a test client.
`SoftAuthenticator` simulates a passkey. See [examples/notes/backend/tests](../examples/notes/backend/tests).

## 7. Deploy

Copy [deploy/](../deploy) into your app, adjust the image names, and follow
[deploy/HETZNER.md](../deploy/HETZNER.md). Set `ALLOWED_HOSTS`, `WEBAUTHN_RP_ID` (your domain)
and `WEBAUTHN_ORIGIN` (`https://your.domain`). Make `backup_days` in your `RetentionPolicy` match
how long your backups are kept.
