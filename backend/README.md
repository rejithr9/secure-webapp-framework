# secure-webapp-framework (Python package `swf`)

The FastAPI back end of the [Secure Web App Framework](https://github.com/rejithr9/secure-webapp-framework):
accounts, mandatory 2FA, passkeys, recovery codes, sessions, CSRF protection, rate limits, per-user
encryption, audit trail, admin area and data retention for private multi-user web apps.

```python
from swf import AppConfig, create_app

app = create_app(AppConfig(name="My App"))
```

Documentation: [building an app](https://github.com/rejithr9/secure-webapp-framework/blob/main/docs/building-an-app.md) ·
[security](https://github.com/rejithr9/secure-webapp-framework/blob/main/docs/security.md). Licence: MIT.
