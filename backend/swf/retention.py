"""Scheduled job: delete all data of users deactivated longer than the retention period."""

import asyncio
import logging

from swf.config import get_settings
from swf.db import session_factory
from swf.services.users import purge_expired

log = logging.getLogger(__name__)


def run_once() -> int:
    with session_factory()() as db:
        removed = purge_expired(db)
    if removed:
        log.info("Retention purge removed %d account(s)", len(removed))
    return len(removed)


async def run_forever() -> None:
    interval = get_settings().retention_job_interval_hours * 3600
    while True:
        try:
            await asyncio.to_thread(run_once)
        except Exception:  # keep the loop alive; the next run retries
            log.exception("Retention purge failed")
        await asyncio.sleep(interval)
