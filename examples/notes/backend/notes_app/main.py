"""The example "Notes" app: everything the framework needs to know about it."""

from pathlib import Path

from swf import AppConfig, Module, RetentionPolicy, TermsConfig, create_app

from notes_app import api

HERE = Path(__file__).parent
MIGRATIONS = HERE / "migrations"
MODEL_MODULES = ["notes_app.models"]

CONFIG = AppConfig(
    name="Notes",
    max_users=10,
    terms=TermsConfig.from_file("1", HERE / "terms.md"),
    retention=RetentionPolicy(max_total_days=182, backup_days=30),
    modules=[Module(name="notes", routers=[api.router], audit_labels=api.AUDIT_LABELS)],
)

app = create_app(CONFIG)
