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

"""Define the POM worker persistence models.

Two tables, both in SEP's own database -- which in the PMM-embedded deployment *is*
PMM's embedded PostgreSQL (all three SEP databases share the ``pmm_embedded_db``
anchor in ``settings.yaml``), so no separate connection is involved.

The probe result is stored here as JSONB and only *summarised* into VictoriaMetrics:
a VM label value is capped at 4096 bytes and silently truncated above it, so
Postgres is the record of truth and VM is the query surface.

This module is loaded by Alembic through ``spec_from_file_location`` without running
the package ``__init__``, so it must not import sibling app modules.
"""

from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Column, Index, JSON
from sqlalchemy import Enum as EnumField
from sqlalchemy.dialects import postgresql
from sqlmodel import Field as SQLField

from app.core.db.models import BaseSQLModel, BaseUUIDSQLModel, DateTimeWithTimezone
from app.core.utils.date_time import utc_now
from app.core.utils.fields import UTCDatetime


class PomRunStatus(StrEnum):
    """Enumerate the terminal and in-flight states of one discovery run.

    :cvar RUNNING: The run is in flight.
    :cvar SUCCESS: Every resolved service probed successfully.
    :cvar PARTIAL: At least one service resolved and probed, at least one did not.
    :cvar FAILED: The run raised before completing, or nothing probed successfully.
    """

    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class NodeResolution(StrEnum):
    """Enumerate how a service was mapped to an executor host.

    ``ORPHANED`` is a first-class outcome, not an error: an inventory row routinely
    outlives the executor that served it, and in this workspace's sandbox 16 of 25
    MongoDB services are in exactly that state. Recording it is what keeps the run
    from silently probing the wrong host.

    :cvar NAME: Matched an executor host by node name.
    :cvar ADDRESS: Matched an executor host by node address.
    :cvar ORPHANED: No live executor host serves this service.
    """

    NAME = "name"
    ADDRESS = "address"
    ORPHANED = "orphaned"


class ProbeStatus(StrEnum):
    """Enumerate the outcome of probing one service.

    :cvar OK: The payload ran and returned a record for this service.
    :cvar FAILED: The payload ran but reported an error for this service.
    :cvar SKIPPED: No probe was attempted, because the service is orphaned.
    """

    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


class PomRun(BaseUUIDSQLModel, table=True):
    """Record one execution of the POM worker job.

    The UUID primary key is the execution id carried into every VictoriaMetrics
    series, so a run in vmui joins back to its rows here.

    :param started_at: When the run began.
    :param finished_at: When the run reached a terminal status; ``None`` while running.
    :param status: The run's lifecycle state.
    :param services_total: MongoDB services found in inventory.
    :param services_resolved: Services mapped to a live executor host.
    :param services_orphaned: Services with no live executor host.
    :param probes_ok: Services that returned a usable probe record.
    :param origin_node: The PMM node this snapshot was taken from, recorded so a
        document can name its own vantage point.
    :param sources: Per-source status and counters -- each
        :class:`~app.sep.apps.pom_worker.facts.SourceResult`'s ``detail``, keyed by
        source. This is the run's receipt: it is what makes a thin snapshot legible as
        "the probe could not reach anything" rather than merely thin.
    :param error: The failure detail when the run itself raised.
    """

    __tablename__ = "pom_run"

    started_at: UTCDatetime = SQLField(
        sa_type=DateTimeWithTimezone, default_factory=utc_now, index=True
    )
    finished_at: UTCDatetime | None = SQLField(
        default=None, sa_type=DateTimeWithTimezone
    )
    status: PomRunStatus = SQLField(
        default=PomRunStatus.RUNNING,
        sa_column=Column(
            EnumField(PomRunStatus, native_enum=False, create_constraint=True),
            nullable=False,
            index=True,
        ),
    )
    services_total: int = SQLField(default=0)
    services_resolved: int = SQLField(default=0)
    services_orphaned: int = SQLField(default=0)
    probes_ok: int = SQLField(default=0)
    origin_node: str | None = SQLField(default=None)
    # Explicit variant rather than ``AutoJSON`` for the reason spelled out on
    # ``PomNode.probe`` below: ``AutoJSON`` silently drops ``none_as_null`` on
    # PostgreSQL, so a Python ``None`` lands as the JSON scalar ``null``.
    sources: dict[str, Any] | None = SQLField(
        default=None,
        sa_column=Column(
            JSON(none_as_null=True).with_variant(
                postgresql.JSONB(none_as_null=True), "postgresql"
            ),
            nullable=True,
        ),
    )
    error: str | None = SQLField(default=None)


class PomNode(BaseSQLModel, table=True):
    """Record one MongoDB service's mapping and probe result within a run.

    One row per service per run, including orphaned services -- the mapping is the
    point of the worker, so a service that could not be probed still gets a row saying
    why.

    :param run_id: The owning :class:`PomRun`.
    :param service_name: The inventory service name.
    :param service_id: The inventory service id.
    :param cluster: The service's ``cluster`` attribute; groups a sharded cluster.
    :param environment: The service's environment label, a filter and display tag.
    :param replication_set: The service's ``replication_set``; empty for mongos.
        Group topologies on this rather than ``cluster`` -- one ``cluster`` value can
        span two generations of members with distinct replica sets.
    :param node_name: The inventory node name, tried first when matching an executor.
    :param node_address: The inventory node address, the fallback match.
    :param port: The service port.
    :param executor_host: The resolved Nomad executor host; ``None`` when orphaned.
    :param resolution: How the executor host was matched, or that it was not.
    :param probe_status: The outcome of probing this service.
    :param task_history_id: The dispatched ``run-python`` run that carried this
        service's probe, or ``None`` when none was dispatched. Persisted so a run's
        failures can be traced into the Tasks API and Nomad without re-deriving
        which dispatch covered which service.
    :param probe: The payload's full record for this service.
    :param facts: The merged field mapping for this service -- every field the run
        settled on, each with the source that supplied it and when it was observed.
        Beside ``probe`` rather than replacing it: ``probe`` is one source's raw output,
        ``facts`` is the reconciled answer across all of them.
    :param error: The per-service failure detail.
    """

    __tablename__ = "pom_node"
    __table_args__ = (Index("ix_pom_node_run_service", "run_id", "service_name"),)

    run_id: UUID = SQLField(foreign_key="pom_run.id", index=True)
    service_name: str = SQLField(index=True)
    service_id: int | None = SQLField(default=None)
    cluster: str | None = SQLField(default=None, index=True)
    replication_set: str | None = SQLField(default=None, index=True)
    environment: str | None = SQLField(default=None, index=True)
    node_name: str | None = SQLField(default=None)
    node_address: str | None = SQLField(default=None)
    port: int | None = SQLField(default=None)
    executor_host: str | None = SQLField(default=None, index=True)
    resolution: NodeResolution = SQLField(
        sa_column=Column(
            EnumField(NodeResolution, native_enum=False, create_constraint=True),
            nullable=False,
            index=True,
        ),
    )
    probe_status: ProbeStatus = SQLField(
        default=ProbeStatus.SKIPPED,
        sa_column=Column(
            EnumField(ProbeStatus, native_enum=False, create_constraint=True),
            nullable=False,
            index=True,
        ),
    )
    task_history_id: int | None = SQLField(default=None, index=True)
    # Not ``AutoJSON``, despite it being the house type for a dialect-aware JSON
    # column. ``none_as_null`` is the point here: without it a Python ``None`` is
    # stored as the JSON scalar ``null`` rather than SQL NULL, so ``probe IS NULL``
    # never matches an orphaned row and any jsonb path operator applied to one
    # fails with "cannot delete path in scalar". ``AutoJSON.load_dialect_impl``
    # builds a fresh ``JSONB()`` for PostgreSQL and so silently drops the flag --
    # verified: it reads back ``none_as_null = False`` on the pg dialect. The
    # explicit variant keeps it on both dialects and still yields JSONB on
    # PostgreSQL, matching the migration.
    probe: dict[str, Any] | None = SQLField(
        default=None,
        sa_column=Column(
            JSON(none_as_null=True).with_variant(
                postgresql.JSONB(none_as_null=True), "postgresql"
            ),
            nullable=True,
        ),
    )
    facts: dict[str, Any] | None = SQLField(
        default=None,
        sa_column=Column(
            JSON(none_as_null=True).with_variant(
                postgresql.JSONB(none_as_null=True), "postgresql"
            ),
            nullable=True,
        ),
    )
    error: str | None = SQLField(default=None)


class PomCluster(BaseSQLModel, table=True):
    """Hold one cluster's assembled status document for one run.

    The worker folds a run's per-service rows into these once; the API serves them
    almost verbatim. Storing the assembled document rather than rebuilding it per
    request is what makes the read path a keyed lookup instead of a join plus a
    regrouping.

    One row per cluster per run — not one row per run — because the API's common
    reads are "every cluster in the latest snapshot" and "this one cluster", and the
    second is a keyed lookup only if clusters are rows.

    :param run_id: The owning :class:`PomRun`.
    :param cluster_id: The stable opaque id, derived from
        ``(environment, cluster, replication_set)``. Stable across runs, so the
        frontend can hold a URL.
    :param name: The cluster label, for display and sorting.
    :param cluster_type: ``replica_set`` / ``sharded_cluster`` / ``standalone``.
    :param environment: The environment label, a first-class filter.
    :param health_status: The rolled-up verdict, promoted out of the document so
        filtering and grouping do not need a JSON path.
    :param members_total: Services in the cluster.
    :param members_observed: …of which answered a probe.
    :param document: The complete status document the API returns.
    """

    __tablename__ = "pom_cluster"
    __table_args__ = (Index("ix_pom_cluster_run_cluster", "run_id", "cluster_id"),)

    run_id: UUID = SQLField(foreign_key="pom_run.id", index=True)
    cluster_id: str = SQLField(index=True)
    name: str = SQLField(index=True)
    cluster_type: str = SQLField(index=True)
    environment: str | None = SQLField(default=None, index=True)
    health_status: str = SQLField(index=True)
    members_total: int = SQLField(default=0)
    members_observed: int = SQLField(default=0)
    # Non-nullable, so the AutoJSON/none_as_null trap cannot apply here at all.
    document: dict[str, Any] = SQLField(
        sa_column=Column(
            JSON(none_as_null=True).with_variant(
                postgresql.JSONB(none_as_null=True), "postgresql"
            ),
            nullable=False,
        )
    )
