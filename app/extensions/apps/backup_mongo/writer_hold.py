# Copyright (C) 2026 Percona LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Serialize a MongoDB backup against Operations through pmm-managed's writer hold.

A PBM-writing backup stops or restarts a managed cluster's members, so it must not
run while an Operations operation holds the cluster. This module acquires the same
Operations writer hold pmm-managed's own backups take, keyed by the backup's job id,
heartbeats it while the backup runs, and releases it when the backup ends.

:func:`writer_hold` is the context manager that owns that lifecycle;
:func:`backup_writer_hold` resolves a backup's PMM service ids first and is the seam
the backup_mongo execution path is meant to wrap its PBM dispatch in. That wiring is
not in place yet: nothing in the live execute path calls this module, so a missed
release cannot leak a cluster lock until the wrapping lands.
"""

__all__ = [
    "WriterHoldConflictError",
    "WriterHoldState",
    "backup_writer_hold",
    "pmm_service_ids_for_backup",
    "writer_hold",
]

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import timedelta

from app.core.utils.date_time import utc_now
from app.extensions.clients.pmm import PMMRemoteAPI, WriterHoldConflict
from app.extensions.deps import get_created_entity, InventoryAPI
from app.extensions.models import SyncInventoryEntityTypeEnum
from app.inventory.models import ServiceTypeEnum

logger = logging.getLogger(__name__)

#: How long a hold's lease lasts before the reaper may reclaim it, refreshed on
#: every heartbeat; the backup releases it explicitly when it ends.
WRITER_HOLD_LEASE = timedelta(minutes=15)
#: Heartbeat cadence, kept shorter than the lease so a live backup never lapses.
WRITER_HOLD_HEARTBEAT_INTERVAL = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class WriterHoldState:
    """Carry whether a writer hold is held for the duration of a backup.

    :param held: Whether a hold was taken; ``False`` when no service is a live
        managed-cluster member and there is nothing to serialize against.
    """

    held: bool


class WriterHoldConflictError(Exception):
    """Signal that Operations holds a conflicting lock, so the backup must not run.

    :param job_id: The backup job that lost the acquire.
    :param service_ids: The PMM service ids the backup would have acted on.
    :param conflict: The Operations holder the acquire lost to.
    """

    def __init__(
        self, job_id: str, service_ids: list[str], conflict: WriterHoldConflict
    ) -> None:
        self.job_id = job_id
        self.service_ids = service_ids
        self.conflict = conflict
        super().__init__(
            f"backup job {job_id} is locked by Operations operation "
            f"{conflict.holder_operation_id} ({conflict.holder_mode})"
        )


async def pmm_service_ids_for_backup(
    inventory_api: InventoryAPI, service_id: int
) -> list[str]:
    """Resolve a backup's local MongoDB service to the PMM service id the hold needs.

    pmm-managed expands the cluster and member locks from the service id, so the one
    service the backup connects PBM to is enough.

    :param inventory_api: The Inventory API that resolves the created entity.
    :param service_id: The local Inventory id of the MongoDB service PBM connects to.
    :return: The one PMM service id, as a single-element list.
    :raises HTTPException: If the service is absent from Inventory.
    :raises ValueError: If the resolved service is not a MongoDB service.
    """
    service = await get_created_entity(
        inventory_api,
        SyncInventoryEntityTypeEnum.SERVICE,
        service_id,
        type=ServiceTypeEnum.MONGODB,
    )
    return [service.external_id]


async def _heartbeat_forever(
    pmm_api: PMMRemoteAPI,
    job_id: str,
    *,
    lease: timedelta,
    interval: timedelta,
) -> None:
    """Extend the hold's lease every ``interval`` until cancelled.

    :param pmm_api: The pmm-managed client to heartbeat through.
    :param job_id: The backup job whose hold to keep alive.
    :param lease: How far ahead each heartbeat sets the deadline.
    :param interval: The wait between heartbeats.
    """
    while True:
        await asyncio.sleep(interval.total_seconds())
        try:
            await pmm_api.heartbeat_writer_hold(job_id, utc_now() + lease)
        except Exception:
            logger.warning(
                "Failed to heartbeat writer hold for backup job %s; retrying next tick",
                job_id,
                exc_info=True,
            )


async def _release_quietly(pmm_api: PMMRemoteAPI, job_id: str) -> None:
    """Release the hold, logging a failure rather than raising.

    Release is a no-op once released, so a retry or a lease-reaper reclaim stays
    correct when this best-effort call loses the network.

    :param pmm_api: The pmm-managed client to release through.
    :param job_id: The backup job whose hold to release.
    """
    try:
        await pmm_api.release_writer_hold(job_id)
    except Exception:
        logger.warning(
            "Failed to release writer hold for backup job %s; the reaper reclaims it "
            "after the lease lapses",
            job_id,
            exc_info=True,
        )


@asynccontextmanager
async def writer_hold(
    pmm_api: PMMRemoteAPI,
    *,
    job_id: str,
    service_ids: list[str],
    lease: timedelta = WRITER_HOLD_LEASE,
    heartbeat_interval: timedelta = WRITER_HOLD_HEARTBEAT_INTERVAL,
) -> AsyncGenerator[WriterHoldState, None]:
    """Hold the Operations writer lock for the body, releasing it on every exit.

    Acquire the hold before the body runs, heartbeat it while the body runs, and
    release it when the body exits for any reason. An acquire that loses a conflict
    raises before the body runs so the backup never starts; an acquire that locks
    nothing (no managed member) yields an unheld state and skips the heartbeat.

    :param pmm_api: The opened pmm-managed client to serialize through.
    :param job_id: The backup job's durable id, keying the hold.
    :param service_ids: The PMM service ids the backup acts on.
    :param lease: The hold's lease, refreshed on every heartbeat.
    :param heartbeat_interval: The wait between heartbeats; keep it under ``lease``.
    :return: The hold state, held for the body.
    :raises WriterHoldConflictError: If Operations holds a conflicting lock.
    :raises HTTPException: If pmm-managed answers the acquire with an error status.
    """
    result = await pmm_api.acquire_writer_hold(job_id, service_ids, utc_now() + lease)
    if result.conflict is not None:
        raise WriterHoldConflictError(job_id, service_ids, result.conflict)
    if not result.acquired:
        yield WriterHoldState(held=False)
        return
    beat = asyncio.create_task(
        _heartbeat_forever(pmm_api, job_id, lease=lease, interval=heartbeat_interval)
    )
    try:
        yield WriterHoldState(held=True)
    finally:
        beat.cancel()
        with suppress(asyncio.CancelledError):
            await beat
        await _release_quietly(pmm_api, job_id)


@asynccontextmanager
async def backup_writer_hold(
    pmm_api: PMMRemoteAPI,
    inventory_api: InventoryAPI,
    *,
    job_id: str,
    service_id: int,
) -> AsyncGenerator[WriterHoldState, None]:
    """Resolve a backup's service and hold the Operations writer lock for the body.

    The backup_mongo execution path is meant to wrap its PBM dispatch in this; that
    wiring is not in place yet.

    :param pmm_api: The opened pmm-managed client to serialize through.
    :param inventory_api: The Inventory API that resolves the backup's service.
    :param job_id: The backup job's durable id, keying the hold.
    :param service_id: The local Inventory id of the MongoDB service PBM connects to.
    :return: The hold state, held for the body.
    :raises WriterHoldConflictError: If Operations holds a conflicting lock.
    :raises HTTPException: If the service is absent or pmm-managed errors the acquire.
    """
    service_ids = await pmm_service_ids_for_backup(inventory_api, service_id)
    async with writer_hold(pmm_api, job_id=job_id, service_ids=service_ids) as state:
        yield state
