"""Alembic environment shared by the framework and the apps built on it.

Driven by `swf.migrate`; apps don't need their own alembic.ini or env.py.
"""

from alembic import context
from sqlalchemy import create_engine

import swf.models  # noqa: F401  (registers framework tables)
from swf.db import Base, UTCDateTime

config = context.config
target_metadata = Base.metadata

for module in config.attributes.get("model_modules", []):
    __import__(module)  # app tables register themselves on the same Base


def _render_item(type_, obj, autogen_context):  # type: ignore[no-untyped-def]
    """Write the framework's UTC datetime type as a plain timezone-aware DateTime in migrations."""
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False


OPTIONS = {"target_metadata": target_metadata, "render_as_batch": True, "render_item": _render_item}


def run_migrations_offline() -> None:
    context.configure(url=config.get_main_option("sqlalchemy.url"), literal_binds=True, **OPTIONS)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, **OPTIONS)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as conn:
        context.configure(connection=conn, **OPTIONS)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
