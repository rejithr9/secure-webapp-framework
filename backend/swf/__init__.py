"""Secure Web App Framework (swf): a reusable, security-first base for multi-user web apps.

Build an app by describing it in an `AppConfig` and calling `create_app`:

    from swf import AppConfig, create_app
    app = create_app(AppConfig(name="My App"))
"""

__version__ = "0.1.0"

from swf.appconfig import AppConfig, Module, RetentionPolicy, SecretProvider, TermsConfig  # noqa: E402
from swf.application import create_app  # noqa: E402

__all__ = [
    "AppConfig",
    "Module",
    "RetentionPolicy",
    "SecretProvider",
    "TermsConfig",
    "create_app",
    "__version__",
]
