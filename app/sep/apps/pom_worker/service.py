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

"""Orchestrate one POM worker run, server-side.

The whole pipeline in one place:

1. list MongoDB services from SEP's inventory;
2. resolve each to the executor host its probe must run on -- strictly, so an
   unmatched service is recorded as orphaned rather than probed somewhere wrong;
3. dispatch the probe payload per executor host and collect NDJSON back;
4. persist the mapping and every probe record to PostgreSQL;
5. emit a VictoriaMetrics summary, if enabled.

Runs inside SEP, so it has the inventory API, the Tasks API, the PMM client, and
SEP's database all directly to hand -- which in the PMM-embedded deployment is PMM's
embedded PostgreSQL.
"""

import logging
from typing import Any
from uuid import UUID

from app.core.config import settings
from app.core.requests import RemoteAPI
from app.core.security import require_internal_token
from app.core.utils.date_time import utc_now
from app.inventory.config import inventory_settings
from app.sep.apps.pom_worker.config import pom_worker_settings
from app.sep.apps.pom_worker.crud import (
    PomClusterManager,
    PomNodeManager,
    PomRunManager,
)
from app.sep.apps.pom_worker.dispatch import HostProbeResult, probe_all
from app.sep.apps.pom_worker.inventory import list_mongodb_services
from app.sep.apps.pom_worker.mapping import (
    get_executor_hosts,
    map_services,
    MappedService,
)
from app.sep.apps.pom_worker.metrics import build_exposition, emit, node_labels
from app.sep.apps.pom_worker.models import (
    NodeResolution,
    PomCluster,
    PomNode,
    PomRun,
    PomRunStatus,
    ProbeStatus,
)
from app.sep.apps.pom_worker.projection import build_cluster_documents, NodeRecord
from app.sep.config import sep_settings
from app.sep.db import get_async_session_maker
from app.sep.deps import get_pmm_api
from app.tasks.config import tasks_settings

logger = logging.getLogger(__name__)


async def _build_clients() -> tuple[RemoteAPI, RemoteAPI]:
    """Construct the inventory and tasks API clients outside request context.

    Mirrors :func:`~app.sep.apps.inventory.deps.get_syncers_standalone`, which is how
    every scheduled SEP job reaches these services.

    :return: The inventory and tasks API clients.
    """
    inventory_api = await settings.get_remote_api(
        endpoint=sep_settings.INVENTORY_ENDPOINT,
        ssl_cafile=settings.SSL_CAFILE,
        ssl_keyfile=inventory_settings.SSL_KEYFILE,
        ssl_certfile=inventory_settings.SSL_CERTFILE,
        logger_name="inventory_api",
    )
    tasks_api = await settings.get_remote_api(
        endpoint=sep_settings.TASKS_ENDPOINT,
        ssl_cafile=settings.SSL_CAFILE,
        ssl_keyfile=tasks_settings.SSL_KEYFILE,
        ssl_certfile=tasks_settings.SSL_CERTFILE,
        logger_name="tasks_api",
    )
    return inventory_api, tasks_api


def _probe_outcome(
    entry: MappedService, host_results: dict[str, HostProbeResult]
) -> tuple[ProbeStatus, dict[str, Any] | None, str | None, int | None]:
    """Resolve one service's probe status, record, error, and dispatched run.

    :param entry: The mapped service.
    :param host_results: Every executor host's probe outcome, keyed by host.
    :return: The probe status, the record if any, the error if any, and the task
        history id of the dispatch that covered this service.
    """
    if not entry.is_resolved:
        return (
            ProbeStatus.SKIPPED,
            None,
            "no live executor host serves this service",
            None,
        )

    result = host_results.get(entry.executor_host or "")
    if result is None:
        return ProbeStatus.FAILED, None, "executor host was never dispatched to", None

    history_id = result.task_history_id
    if result.error and not result.records:
        return ProbeStatus.FAILED, None, result.error, history_id

    record = result.records.get(entry.service.name)
    if record is None:
        return (
            ProbeStatus.FAILED,
            None,
            f"probe ran on {entry.executor_host} but reported nothing for this service",
            history_id,
        )
    if record.get("status") != "ok":
        return ProbeStatus.FAILED, record, record.get("error"), history_id
    return ProbeStatus.OK, record, None, history_id


async def run_discovery(execution_id: UUID | None = None) -> UUID:
    """Execute one full discovery run and return its execution id.

    ``execution_id`` lets a caller reserve the id before the work starts: the API's
    trigger endpoint creates the ``PomRun`` row so it can answer ``202`` with a
    run id the client can immediately poll, then hands the id here. Called with
    ``None`` -- from the CLI or a beat schedule -- this mints its own.

    :param execution_id: An already-created run's id, or ``None`` to create one.
    :return: The run's id, which is also the ``execution_id`` label on every emitted
        VictoriaMetrics series.
    """
    session_maker = get_async_session_maker()
    if execution_id is None:
        async with session_maker() as session:
            run = await PomRunManager.save(session, PomRun())
            execution_id = run.id
    logger.info("POM worker: run %s started", execution_id)

    # The probe phase can take minutes, so the session is not held across it.
    try:
        rows, host_results, mapped = await _collect(execution_id)
    except Exception as err:
        logger.exception("POM worker: run %s failed", execution_id)
        async with session_maker() as session:
            failed = await PomRunManager.get(session, id=execution_id)
            failed.status = PomRunStatus.FAILED
            failed.finished_at = utc_now()
            failed.error = f"{type(err).__name__}: {err}"
            await PomRunManager.save(session, failed)
        raise

    probes_ok = sum(1 for row in rows if row.probe_status is ProbeStatus.OK)
    resolved = sum(1 for entry in mapped if entry.is_resolved)
    orphaned = len(mapped) - resolved

    # The node rows, the cluster snapshot and the terminal run status are written in
    # ONE transaction. That is what makes a reader see a complete snapshot or the
    # previous one, never a half-written topology: the API only ever reads clusters
    # belonging to a run whose status is already terminal.
    clusters = build_cluster_documents(_node_records(rows), utc_now())
    async with session_maker() as session:
        await PomNodeManager.save_batch(session, *rows)
        await PomClusterManager.save_batch(
            session,
            *(
                PomCluster(
                    run_id=execution_id,
                    cluster_id=document["id"],
                    name=document["name"],
                    cluster_type=document["type"],
                    environment=document["environment"],
                    health_status=document["health"]["status"],
                    members_total=document["members_total"],
                    members_observed=document["members_observed"],
                    document=document,
                )
                for document in clusters
            ),
        )
        finished = await PomRunManager.get(session, id=execution_id)
        finished.status = (
            PomRunStatus.SUCCESS
            if resolved and probes_ok == resolved
            else PomRunStatus.PARTIAL
            if probes_ok
            else PomRunStatus.FAILED
        )
        finished.finished_at = utc_now()
        finished.services_total = len(mapped)
        finished.services_resolved = resolved
        finished.services_orphaned = orphaned
        finished.probes_ok = probes_ok
        await PomRunManager.save(session, finished)

    logger.info(
        "POM worker: run %s finished -- %d service(s): %d resolved, %d orphaned, "
        "%d probed ok",
        execution_id,
        len(mapped),
        resolved,
        orphaned,
        probes_ok,
    )

    await _emit_metrics(execution_id, rows, host_results)
    return execution_id


async def _collect(
    execution_id: UUID,
) -> tuple[list[PomNode], dict[str, HostProbeResult], list[MappedService]]:
    """Run steps 1-3 and assemble the rows to persist.

    :param execution_id: The owning run's id.
    :return: The rows to persist, the per-host probe results, and the mapping.
    """
    inventory_api, tasks_api = await _build_clients()

    # Both services authenticate; outside request context there is no user session to
    # borrow, so the run rides the internal service token the same way the scheduled
    # inventory sync does. `auth` is a sync context manager setting a header for its
    # block, so every call that needs it has to be made inside.
    token = require_internal_token()
    with inventory_api.auth(token), tasks_api.auth(token):
        services = await list_mongodb_services(inventory_api)
        executor_hosts = await get_executor_hosts(tasks_api)
        mapped = map_services(services, executor_hosts)
        host_results = await probe_all(tasks_api, mapped)

    rows = []
    for entry in mapped:
        probe_status, record, error, history_id = _probe_outcome(entry, host_results)
        rows.append(
            PomNode(
                run_id=execution_id,
                service_name=entry.service.name,
                service_id=entry.service.service_id,
                cluster=entry.service.cluster,
                replication_set=entry.service.replication_set,
                environment=entry.service.environment,
                node_name=entry.service.node_name,
                node_address=entry.service.node_address,
                port=entry.service.port,
                executor_host=entry.executor_host,
                resolution=entry.resolution,
                probe_status=probe_status,
                task_history_id=history_id,
                probe=record,
                error=error,
            )
        )
    return rows, host_results, mapped


def _node_records(rows: list[PomNode]) -> list[NodeRecord]:
    """Adapt persisted node rows into the projection's plain input type.

    Kept as an explicit adapter so ``projection`` never imports a SQLModel and stays
    testable without a database.

    :param rows: The run's node rows.
    :return: The projection input.
    """
    return [
        NodeRecord(
            service_name=row.service_name,
            service_id=row.service_id,
            cluster=row.cluster,
            replication_set=row.replication_set,
            environment=row.environment,
            port=row.port,
            executor_host=row.executor_host,
            resolution=str(row.resolution),
            probe_status=str(row.probe_status),
            probe=row.probe,
        )
        for row in rows
    ]


async def _emit_metrics(
    execution_id: UUID,
    rows: list[PomNode],
    host_results: dict[str, HostProbeResult],
) -> None:
    """Emit the run's VictoriaMetrics summary, if enabled.

    :param execution_id: The run's id.
    :param rows: The persisted rows.
    :param host_results: The per-host probe results, used for the raw-JSON series.
    """
    if not pom_worker_settings.EMIT_METRICS:
        logger.info("POM worker: emit_metrics is off; no metrics written")
        return

    labels = [
        node_labels(
            service_name=row.service_name,
            cluster=row.cluster,
            replication_set=row.replication_set,
            executor_host=row.executor_host,
            resolution=NodeResolution(row.resolution),
            probe_status=ProbeStatus(row.probe_status),
            probe=row.probe,
        )
        for row in rows
    ]
    raw = None
    if pom_worker_settings.EMIT_RAW_JSON:
        raw = {
            "execution_id": str(execution_id),
            "hosts": {
                host: {
                    "task_history_id": result.task_history_id,
                    "error": result.error,
                    "services": sorted(result.records),
                }
                for host, result in host_results.items()
            },
        }

    exposition = build_exposition(execution_id, int(utc_now().timestamp()), labels, raw)
    pmm_api = await get_pmm_api()
    if pmm_api is None:
        logger.warning(
            "POM worker: no PMM client configured; cannot reach VictoriaMetrics. "
            "The run's results are still in Postgres."
        )
        return
    await emit(pmm_api, exposition)
