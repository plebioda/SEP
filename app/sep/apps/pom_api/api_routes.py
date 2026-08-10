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

"""Serve POM's read API and its discovery trigger.

Mounted automatically at ``/api/apps/pom_api`` -- the registry includes any app's
``api_router`` under its key -- so nothing here wires itself up. Two dependencies
come from that mount and are worth knowing rather than re-declaring:

* ``IsApiAuthenticated`` on all of ``/api``, so every route below requires a caller.
* ``RequireBearerForUnsafeMethods`` on ``/apps``, so ``POST /discovery/runs``
  specifically needs a **bearer token** -- a browser session cookie can read the
  cluster list but cannot trigger a run.

Nothing here queries VictoriaMetrics. Every list and detail response is served from
the stored snapshot, which is what keeps them fast and cacheable; time-series data
belongs behind a separate, explicitly bounded endpoint.
"""

import logging
from datetime import timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from fastapi.security import HTTPBearer
from sqlmodel import select

from app.core.exceptions import (
    HTTPConflictException,
    HTTPNotFoundException,
    HTTPServiceUnavailableException,
)
from app.core.utils.date_time import utc_now
from app.sep.apps.pom_api.crud import (
    cluster_for_run,
    clusters_for_run,
    get_run,
    latest_snapshot_run,
    recent_runs,
    running_run,
)
from app.sep.apps.pom_api.schemas import (
    ClusterDetailResponse,
    ClusterListResponse,
    DiscoveryRunAccepted,
    DiscoveryRunResponse,
    GroupCount,
    HealthSummary,
    RunCounts,
    RunError,
)
from app.sep.apps.pom_worker.crud import PomRunManager
from app.sep.apps.pom_worker.models import (
    NodeResolution,
    PomCluster,
    PomNode,
    PomRun,
    PomRunStatus,
)
from app.sep.apps.pom_worker.projection import build_summary
from app.sep.deps import SessionDep

logger = logging.getLogger(__name__)

#: Declared purely so Swagger UI at ``/api/docs`` renders an **Authorize** box and
#: attaches ``Authorization: Bearer <token>`` to "Try it out" calls.
#:
#: It enforces nothing: ``auto_error=False`` means a request without the header
#: passes straight through, and the real check stays SEP's ``IsApiAuthenticated`` on
#: the parent ``/api`` router. Without this, Swagger sends no credentials at all --
#: fine for a GET from a logged-in browser, which rides the session cookie, but
#: ``POST /discovery/runs`` needs a bearer (``RequireBearerForUnsafeMethods`` on
#: ``/apps``) and would always answer 401 from the page.
#:
#: SEP declares an ``OAuth2PasswordBearer`` scheme globally, but only 5 of ~175
#: operations reference it and no app route does, so the Authorize button does not
#: reach these endpoints by default. A plain bearer box is also the one form that
#: works whichever auth provider is configured -- the password grant behind that
#: OAuth2 scheme is unusable when Grafana is the active provider.
_swagger_bearer = HTTPBearer(
    scheme_name="SEPBearerToken",
    description=(
        "Paste a SEP bearer token, then Authorize. Get one with `./om pom token`, "
        "or from SEP with `get_internal_token()`. This is the only scheme that "
        "works here \u2014 the OAuth2 password flow above needs credentials that do "
        "not exist when Grafana is the auth provider."
    ),
    auto_error=False,
)

router = APIRouter(dependencies=[Depends(_swagger_bearer)])

#: How old a snapshot may be before responses mark it stale. It is still served --
#: the UI shows stale data with a marker rather than an error page.
SNAPSHOT_GRACE = timedelta(minutes=30)

#: How long a ``RUNNING`` row is trusted before the trigger assumes its process died.
#: Without this a crashed run wedges the trigger permanently, which is the same
#: failure already recorded in bugs/sep-stale-running-blocks-execution.md.
RUN_STALE_AFTER = timedelta(minutes=30)

#: Display labels for the health buckets the list view groups by, worst first.
_HEALTH_LABELS = (
    ("critical", "Critical"),
    ("warning", "Warning"),
    ("unknown", "Unknown"),
    ("ok", "Healthy"),
)


def _envelope(run: PomRun, documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the provenance fields every snapshot-backed response repeats.

    :param run: The run the snapshot came from.
    :param documents: The cluster documents in it.
    :return: The envelope fields.
    """
    observed = [
        doc["health"]["observed_at"]
        for doc in documents
        if doc["health"]["observed_at"]
    ]
    generated_at = run.finished_at or run.started_at
    return {
        "generated_at": generated_at,
        "observed_at": max(observed) if observed else None,
        "stale": utc_now() - generated_at > SNAPSHOT_GRACE,
        "schema_version": next((doc.get("schema_version", 1) for doc in documents), 1),
        "run_id": run.id,
    }


async def _require_snapshot(session: SessionDep) -> tuple[PomRun, list[PomCluster]]:
    """Return the newest complete snapshot, or fail with 503.

    :param session: The database session.
    :return: The run and its cluster rows.
    :raises HTTPServiceUnavailableException: When no discovery has ever finished.
    """
    run = await latest_snapshot_run(session)
    if run is None:
        raise HTTPServiceUnavailableException(
            "No discovery run has completed yet; trigger one with POST /discovery/runs."
        )
    return run, await clusters_for_run(session, run.id)


@router.get("/clusters", response_model=ClusterListResponse)
async def list_clusters(
    session: SessionDep,
    health: str | None = Query(None, description="Filter by health status."),
    cluster_type: str | None = Query(
        None, alias="type", description="Filter by topology type."
    ),
    environment: str | None = Query(None, description="Filter by environment label."),
) -> ClusterListResponse:
    """Return every cluster in the newest snapshot, with summary and group counts.

    Member lists are omitted -- the list view does not render them, and including
    them would multiply the response size by the fleet's node count for no benefit.
    Fetch one cluster's detail for its members.

    Filters are applied **after** the summary is computed, so the summary always
    describes the whole fleet while ``clusters`` describes the current filter. That
    is what lets the UI show "3 of 18" without a second request.

    :param session: The database session.
    :param health: Optional health-status filter.
    :param cluster_type: Optional topology-type filter.
    :param environment: Optional environment filter.
    :return: The cluster list response.
    :raises HTTPServiceUnavailableException: When no snapshot exists yet.
    """
    run, rows = await _require_snapshot(session)
    documents = [row.document for row in rows]

    summary = build_summary(documents)
    groups = [
        GroupCount(key=key, label=label, count=summary["by_health"].get(key, 0))
        for key, label in _HEALTH_LABELS
        if summary["by_health"].get(key)
    ]

    selected = [
        doc
        for doc in documents
        if (health is None or doc["health"]["status"] == health)
        and (cluster_type is None or doc["type"] == cluster_type)
        and (environment is None or doc["environment"] == environment)
    ]
    # The list view never renders members; detail does.
    listed = [{k: v for k, v in doc.items() if k != "members"} for doc in selected]

    return ClusterListResponse(
        **_envelope(run, documents),
        summary=HealthSummary(**summary),
        groups=groups,
        clusters=listed,
    )


@router.get("/clusters/{cluster_id}", response_model=ClusterDetailResponse)
async def get_cluster(cluster_id: str, session: SessionDep) -> ClusterDetailResponse:
    """Return one cluster's full document, members included.

    :param cluster_id: The opaque cluster id from the list response.
    :param session: The database session.
    :return: The cluster detail response.
    :raises HTTPNotFoundException: When the snapshot holds no such cluster.
    :raises HTTPServiceUnavailableException: When no snapshot exists yet.
    """
    run, rows = await _require_snapshot(session)
    row = await cluster_for_run(session, run.id, cluster_id)
    if row is None:
        raise HTTPNotFoundException(f"No cluster with id {cluster_id}")
    return ClusterDetailResponse(
        **_envelope(run, [r.document for r in rows]), cluster=row.document
    )


def _run_response(run: PomRun, errors: list[RunError]) -> DiscoveryRunResponse:
    """Shape one run row for the wire.

    :param run: The run row.
    :param errors: Its recorded errors.
    :return: The run response.
    """
    return DiscoveryRunResponse(
        run_id=run.id,
        status=str(run.status),
        started_at=run.started_at,
        finished_at=run.finished_at,
        counts=RunCounts(
            services_total=run.services_total,
            services_resolved=run.services_resolved,
            services_orphaned=run.services_orphaned,
            probes_ok=run.probes_ok,
        ),
        errors=errors,
    )


@router.get("/discovery/runs", response_model=list[DiscoveryRunResponse])
async def list_runs(
    session: SessionDep,
    limit: int = Query(20, ge=1, le=100),
) -> list[DiscoveryRunResponse]:
    """Return recent discovery runs, newest first.

    Errors are omitted from the list; fetch one run for its detail.

    :param session: The database session.
    :param limit: How many runs to return.
    :return: The runs.
    """
    return [_run_response(run, []) for run in await recent_runs(session, limit)]


@router.get("/discovery/runs/{run_id}", response_model=DiscoveryRunResponse)
async def get_discovery_run(run_id: UUID, session: SessionDep) -> DiscoveryRunResponse:
    """Return one discovery run with its per-service errors.

    :param run_id: The run to fetch.
    :param session: The database session.
    :return: The run response.
    :raises HTTPNotFoundException: When the run is unknown.
    """
    run = await get_run(session, run_id)
    if run is None:
        raise HTTPNotFoundException(f"No discovery run with id {run_id}")

    errors: list[RunError] = []
    if run.error:
        errors.append(RunError(scope="run", code="run_failed", message=run.error))

    failed = await session.exec(
        select(PomNode).where(PomNode.run_id == run_id, PomNode.error.is_not(None))  # type: ignore[union-attr]
    )
    errors.extend(
        RunError(
            scope="service",
            service_name=row.service_name,
            # An orphaned service is the normal state of an inventory that syncs
            # while hosts come and go -- reported, but not as a probe failure.
            # Compare against the enum, not a string literal: SQLAlchemy stores
            # the member NAME ("ORPHANED") while ``str()`` on a StrEnum yields its
            # VALUE ("orphaned"), so a literal comparison silently never matches.
            code=(
                "executor_not_found"
                if row.resolution == NodeResolution.ORPHANED
                else "probe_failed"
            ),
            message=row.error or "",
        )
        for row in failed.all()
    )
    return _run_response(run, errors)


@router.post(
    "/discovery/runs",
    response_model=DiscoveryRunAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_discovery(session: SessionDep) -> DiscoveryRunAccepted:
    """Queue a discovery run and return its id immediately.

    Never performs discovery synchronously: a run takes tens of seconds and scales
    with the number of executor hosts. The row is created here so the caller gets an
    id it can poll straight away, then the id is handed to the worker.

    :param session: The database session.
    :return: The accepted run.
    :raises HTTPConflictException: When a run is already in flight.
    """
    # Imported here, not at module scope: importing the worker's Celery module pulls
    # in the Celery app, which the API process does not otherwise need.
    from app.sep.apps.pom_worker.celery import run_pom_discovery

    in_flight = await running_run(session)
    if in_flight is not None and utc_now() - in_flight.started_at < RUN_STALE_AFTER:
        raise HTTPConflictException(
            f"Discovery run {in_flight.id} is already in progress; "
            "wait for it to finish."
        )
    if in_flight is not None:
        # Past the cutoff its process is gone. Fail it rather than let a stranded
        # row block every future trigger.
        logger.warning(
            "POM API: run %s has been RUNNING since %s; marking it failed so a new "
            "run can start",
            in_flight.id,
            in_flight.started_at,
        )
        in_flight.status = PomRunStatus.FAILED
        in_flight.finished_at = utc_now()
        in_flight.error = "abandoned: no completion recorded before the stale cutoff"
        await PomRunManager.save(session, in_flight)

    run = await PomRunManager.save(session, PomRun())
    run_pom_discovery.delay(str(run.id))
    logger.info("POM API: queued discovery run %s", run.id)
    return DiscoveryRunAccepted(
        run_id=run.id, status=str(run.status), started_at=run.started_at
    )
