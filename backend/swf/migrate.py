"""Database migrations for the framework plus any app built on it.

The framework's migrations form the `swf` branch. An app keeps its own migrations in its
own folder as a separate branch that depends on the framework's, so both evolve
independently. `upgrade()` applies every branch.
"""

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

FRAMEWORK_DIR = Path(__file__).parent / "migrations"
FRAMEWORK_BASE_REVISION = "swf_0001"

logging.getLogger("alembic.runtime.plugins").setLevel(logging.WARNING)  # very chatty at INFO


def make_config(
    database_url: str, app_versions: str | Path | None = None, model_modules: list[str] | None = None
) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(FRAMEWORK_DIR))
    locations = [str(FRAMEWORK_DIR / "versions")]
    if app_versions is not None:
        locations.append(str(app_versions))
    cfg.set_main_option("version_locations", " ".join(locations))
    cfg.set_main_option("path_separator", "space")
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    cfg.attributes["model_modules"] = model_modules or []
    return cfg


def upgrade(database_url: str, app_versions: str | Path | None = None, model_modules: list[str] | None = None) -> None:
    command.upgrade(make_config(database_url, app_versions, model_modules), "heads")


def make_revision(
    database_url: str, app_versions: str | Path, branch: str, message: str, model_modules: list[str]
) -> None:
    """Autogenerate an app migration from the app's models (on its own branch)."""
    cfg = make_config(database_url, app_versions, model_modules)
    Path(app_versions).mkdir(parents=True, exist_ok=True)
    command.upgrade(cfg, "heads")  # autogenerate compares against an up-to-date database
    has_branch = any(p.suffix == ".py" for p in Path(app_versions).glob("*.py"))
    if has_branch:
        command.revision(cfg, message=message, autogenerate=True, head=f"{branch}@head")
    else:
        command.revision(
            cfg,
            message=message,
            autogenerate=True,
            head="base",
            branch_label=branch,
            version_path=str(app_versions),
            depends_on=FRAMEWORK_BASE_REVISION,
        )
