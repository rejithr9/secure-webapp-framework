"""Server commands for the Notes app: python -m notes_app.cli --help"""

from swf.cli import run

from notes_app.main import CONFIG, MIGRATIONS, MODEL_MODULES

if __name__ == "__main__":
    run(CONFIG, app_versions=MIGRATIONS, model_modules=MODEL_MODULES, branch="notes")
