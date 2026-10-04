# Back-end image for any swf app. Build context: the repository root.
#   APP_DIR      folder with the app's pyproject.toml (relative to the context)
#   APP_PACKAGE  the app's Python package (it must have main.py with `app` and cli.py)
FROM python:3.12-slim

ARG APP_DIR=backend
ARG APP_PACKAGE
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 APP_PACKAGE=${APP_PACKAGE}

RUN useradd --create-home --uid 10001 app
COPY . /src
# In the framework repository the framework itself is installed from source first;
# an app repository pins a framework release in its own pyproject.toml instead.
RUN if [ -f /src/backend/swf/__init__.py ]; then pip install /src/backend; fi \
 && pip install "/src/${APP_DIR}" \
 && rm -rf /src

USER app
WORKDIR /home/app
EXPOSE 8000
# One process on purpose: rate limits are kept in memory. Caddy in front terminates TLS.
CMD ["sh", "-c", "python -m ${APP_PACKAGE}.cli migrate && exec uvicorn ${APP_PACKAGE}.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
