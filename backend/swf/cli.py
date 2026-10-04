"""Server command line for any swf app.

An app exposes it from its own module, for example `myapp/cli.py`:

    from swf.cli import run
    from myapp.main import CONFIG, MIGRATIONS, MODEL_MODULES
    if __name__ == "__main__":
        run(CONFIG, app_versions=MIGRATIONS, model_modules=MODEL_MODULES, branch="myapp")

Commands:
  generate-master-key        print a new MASTER_KEY value
  migrate                    apply all database migrations (framework + app)
  make-migration -m MSG      autogenerate an app migration from the app's models
  create-admin USERNAME      create an admin account; prints a one-time password
  purge-retention            run the retention purge now
"""

import argparse
import base64
import os
import sys
from pathlib import Path

from swf.appconfig import AppConfig, set_app_config
from swf.errors import AppError


def main(
    config: AppConfig,
    argv: list[str] | None = None,
    app_versions: str | Path | None = None,
    model_modules: list[str] | None = None,
    branch: str | None = None,
) -> int:
    parser = argparse.ArgumentParser(prog="cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("generate-master-key", help="print a new random MASTER_KEY")
    sub.add_parser("migrate", help="apply all database migrations")
    make = sub.add_parser("make-migration", help="autogenerate an app migration")
    make.add_argument("-m", "--message", required=True)
    create = sub.add_parser("create-admin", help="create an admin account")
    create.add_argument("username")
    create.add_argument(
        "--allow-non-interactive",
        action="store_true",
        help="print the one-time password even when the output is not a terminal (it may end up in logs)",
    )
    sub.add_parser("purge-retention", help="delete data of users past the retention period")
    args = parser.parse_args(argv)

    if args.command == "generate-master-key":
        print(base64.urlsafe_b64encode(os.urandom(32)).decode())
        return 0

    set_app_config(config)
    from swf import migrate
    from swf.config import get_settings

    if args.command == "migrate":
        migrate.upgrade(get_settings().database_url, app_versions, model_modules)
        print("Database is up to date.")
        return 0

    if args.command == "make-migration":
        if app_versions is None or branch is None:
            print("This app has no migrations folder configured.", file=sys.stderr)
            return 2
        migrate.make_revision(get_settings().database_url, app_versions, branch, args.message, model_modules or [])
        return 0

    from swf.db import session_factory
    from swf.services import audit, users

    if args.command == "create-admin":
        # The one-time password is shown once, to the person at the terminal. Refuse when the
        # output goes somewhere else (a file, a pipe, a log collector) unless explicitly allowed.
        if not sys.stdout.isatty() and not args.allow_non_interactive:
            print(
                "Run this in an interactive terminal, so the one-time password isn't written to a log. "
                "(Use --allow-non-interactive to override.)",
                file=sys.stderr,
            )
            return 2
        with session_factory()() as db:
            user, initial_password = users.create_user(db, args.username, "admin")
            audit.record_admin(db, "user_created", actor=None, target=user, details={"role": "admin", "via": "cli"})
            db.commit()
        print(f"Admin '{user.username}' created.")
        # Intentional, one-time display to the operator's terminal (see the check above); never logged.
        print(f"One-time password (shown once, change it at first sign-in): {initial_password}")
        return 0

    if args.command == "purge-retention":
        with session_factory()() as db:
            removed = users.purge_expired(db)
        print(f"Removed {len(removed)} account(s).")
        return 0
    return 1


def run(config: AppConfig, **kwargs) -> None:  # type: ignore[no-untyped-def]
    try:
        sys.exit(main(config, **kwargs))
    except AppError as exc:
        print(exc.message, file=sys.stderr)
        sys.exit(2)
