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
    get_run,
    latest_snapshot_run,
    recent_runs,
    running_run,
    snapshot_for_run,
)
from app.sep.apps.pom_api.schemas import (
    DiscoveryRunAccepted,
    DiscoveryRunResponse,
    RunCounts,
    RunError,
    SnapshotEnvelope,
    TopologyEnvironment,
    TopologyResponse,
    TopologySummary,
)
from app.sep.apps.pom_worker.config import pom_worker_settings
from app.sep.apps.pom_worker.crud import PomRunManager
from app.sep.apps.pom_worker.models import (
    NodeResolution,
    PomNode,
    PomRun,
)
from app.sep.apps.pom_worker.reap import sweep_stale_runs
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


def _envelope(run: PomRun, document: dict[str, Any]) -> dict[str, Any]:
    """Build the provenance fields the topology response carries.

    :param run: The run the snapshot came from.
    :param document: The topology document.
    :return: The envelope fields.
    """
    generated_at = run.finished_at or run.started_at
    return {
        "generated_at": generated_at,
        # The document is assembled in one pass from one set of queries, so its
        # observation time is the run's -- there is no per-cluster spread to fold.
        "observed_at": generated_at,
        "stale": utc_now() - generated_at > SNAPSHOT_GRACE,
        "schema_version": document.get("schema_version", 1),
        "run_id": run.id,
    }


@router.get("/topology", response_model=TopologyResponse)
async def get_topology(session: SessionDep) -> TopologyResponse:
    """Return the newest complete topology snapshot.

    Served whole rather than paged: the document is one nested tree and the UI renders
    all of it. A stale snapshot is returned with ``snapshot.stale`` set rather than
    replaced by an error, so the page shows the last known estate with a marker instead
    of going blank whenever collection lapses.

    :param session: The database session.
    :return: The topology response.
    :raises HTTPServiceUnavailableException: When no discovery has ever finished.
    """
    run = await latest_snapshot_run(session)
    snapshot = await snapshot_for_run(session, run.id) if run else None
    if run is None or snapshot is None:
        raise HTTPServiceUnavailableException(
            "No discovery run has completed yet; trigger one with POST /discovery/runs."
        )
    document = snapshot.document
    return TopologyResponse(
        snapshot=SnapshotEnvelope(**_envelope(run, document)),
        origin_node=document.get("origin_node"),
        source_queries=document.get("source_queries", []),
        summary=TopologySummary(**(document.get("summary") or {})),
        environments=[
            TopologyEnvironment(**environment)
            for environment in document.get("environments", [])
        ],
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

    # Reap before reading, so a row whose process died cannot answer 409 on behalf of
    # a run nothing is executing. ``reap_stale_pom_runs`` normally gets there first;
    # this covers the deployment whose beat is not running, where the sweep would
    # never fire and a stranded row would otherwise wedge the trigger permanently.
    # Whatever is still RUNNING afterwards is young enough to believe. The sweep
    # commits in a session of its own (see its docstring), so this reads the result
    # back rather than relying on anything it left in ``session``.
    await sweep_stale_runs(pom_worker_settings.STALE_RUN_AFTER)
    in_flight = await running_run(session)
    if in_flight is not None:
        raise HTTPConflictException(
            f"Discovery run {in_flight.id} is already in progress; "
            "wait for it to finish."
        )

    run = await PomRunManager.save(session, PomRun())
    run_pom_discovery.delay(str(run.id))
    logger.info("POM API: queued discovery run %s", run.id)
    return DiscoveryRunAccepted(
        run_id=run.id, status=str(run.status), started_at=run.started_at
    )
