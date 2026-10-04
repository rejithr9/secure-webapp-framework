# Front end + reverse proxy. Build context: the repository root.
#   FRONTEND_DIR  folder with the app's front end (relative to the context)
FROM node:22-alpine AS build
ARG FRONTEND_DIR=frontend
WORKDIR /src
COPY . .
# In the framework repository, build the @swf/web library first (the example links to it).
RUN if [ -f frontend/src/SwfApp.tsx ] && [ "${FRONTEND_DIR}" != "frontend" ]; then cd frontend && npm ci && npm run build; fi
RUN cd "${FRONTEND_DIR}" && npm ci && npm run build

FROM caddy:2-alpine
ARG FRONTEND_DIR=frontend
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /src/${FRONTEND_DIR}/dist /srv
