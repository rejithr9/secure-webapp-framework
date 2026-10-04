#!/usr/bin/env bash
# Nightly encrypted database backup with restic (e.g. to a Hetzner Storage Box).
# Run from cron or a systemd timer as the deploy user (see HETZNER.md).
set -euo pipefail

cd "$(dirname "$0")"
set -a
# shellcheck disable=SC1091
source .env
set +a
: "${BACKUP_KEEP_DAYS:?Set BACKUP_KEEP_DAYS in deploy/.env (must match RetentionPolicy.backup_days)}"

# Stream a compressed dump straight into restic (encrypted client-side, nothing left on disk).
docker compose exec -T db pg_dump -U app -d app --format=custom \
  | restic backup --stdin --stdin-filename "app.dump" --tag db

# Keep backups no longer than the app's RetentionPolicy promises (backup_days), so data from
# deleted or expired accounts never outlives that promise in old snapshots.
restic forget --tag db --keep-within "${BACKUP_KEEP_DAYS}d" --prune

# Check a sample of the repository data.
restic check --read-data-subset=5%
