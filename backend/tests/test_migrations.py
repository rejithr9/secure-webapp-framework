"""The migrations create exactly the tables the models describe, and can be rolled back."""

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from swf import migrate
from swf.db import Base


def test_migrations_match_models(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'migrate.db'}"
    migrate.upgrade(url)

    engine = create_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []

    command.downgrade(migrate.make_config(url), "base")
    engine.dispose()
