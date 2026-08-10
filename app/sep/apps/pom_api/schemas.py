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

"""Define the response models POM's read API returns.

These are the OpenAPI contract, and therefore the input to the generated frontend
client -- run ``make regen-specs`` after changing one. They are declared explicitly
rather than returning ORM rows so the wire shape is reviewable in one file and does
not drift with the tables behind it.

Two rules of the topology contract show up directly here:

* **Every envelope carries staleness.** ``generated_at`` / ``observed_at`` / ``stale``
  are on the response, not derived by the caller, and a stale snapshot is still
  returned rather than replaced by an error.
* **A null means "not observable", never "zero".** Cluster documents carry an
  ``unavailable`` map naming the reason for each null, so the UI can render "-" with
  a cause instead of a misleading 0.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SnapshotEnvelope(BaseModel):
    """Carry the provenance every snapshot-backed response repeats.

    :param generated_at: When the snapshot was assembled by the worker.
    :param observed_at: The newest observation in it, or ``None`` when nothing in the
        snapshot was observed at all.
    :param stale: Whether the snapshot is older than the configured grace period.
    :param schema_version: The document schema version the worker wrote.
    :param run_id: The discovery run the snapshot came from.
    """

    generated_at: datetime
    observed_at: datetime | None = None
    stale: bool = False
    schema_version: int = 1
    run_id: UUID


class TopologyService(BaseModel):
    """One monitored MongoDB service, as the topology document records it.

    Two conventions the frontend depends on, both deliberate:

    * ``cpu_usage_percent`` and ``connections_free_percent`` are **-1 when not
      measured**, never null and never 0. Zero CPU is a real reading, so a numeric
      sentinel keeps "idle" and "unknown" apart in a column that must stay numeric.
    * ``replication_lag_seconds`` and ``oplog_window_seconds`` *are* null when they do
      not apply -- a router and a standalone have no replica-set oplog, and a
      single-member set has no peer to lag behind. Null here means "not a thing for
      this topology", which is different from -1's "we could not measure it".

    :param service_name: The inventory service name.
    :param host: The node the service runs on.
    :param endpoint: ``host:port`` as the replica set addresses the member.
    :param service_id: PMM's service UUID.
    :param service_type: Always ``mongodb`` today.
    :param version: The running server version.
    :param vendor: ``MongoDB`` or ``Percona``.
    :param edition: ``Community`` or ``Enterprise``.
    :param replication_set: The replica set, or ``None`` for a router or standalone.
    :param state: ``PRIMARY`` / ``SECONDARY`` / ``ARBITER``, or ``None``.
    :param status: ``UP`` or ``DOWN``.
    :param cpu_usage_percent: CPU percentage, or ``-1``.
    :param connections_free_percent: Free-connection percentage, or ``-1``.
    :param process_role: ``mongod``, ``mongos``, ``configsvr`` or ``shardsvr``.
    :param replication_lag_seconds: Seconds behind the primary, or ``None``.
    :param oplog_window_seconds: Seconds of oplog history, or ``None``.
    """

    service_name: str
    host: str | None = None
    endpoint: str | None = None
    service_id: str | None = None
    service_type: str | None = None
    version: str | None = None
    vendor: str | None = None
    edition: str | None = None
    replication_set: str | None = None
    state: str | None = None
    status: str
    cpu_usage_percent: float = -1
    connections_free_percent: float = -1
    process_role: str
    replication_lag_seconds: float | None = None
    oplog_window_seconds: float | None = None


class TopologyCluster(BaseModel):
    """One cluster or replica set.

    :param name: The cluster label, or ``None`` when the services carry none.
    :param services: Its services, ordered by name.
    """

    name: str | None = None
    services: list[TopologyService] = Field(default_factory=list)


class TopologyEnvironment(BaseModel):
    """One monitoring environment.

    :param env_name: The environment label, or ``None`` when unset.
    :param clusters: Its clusters, ordered by name.
    """

    env_name: str | None = None
    clusters: list[TopologyCluster] = Field(default_factory=list)


class TopologySummary(BaseModel):
    """Fleet-level counts, so the UI need not re-derive them.

    :param environments: Environments in the snapshot.
    :param clusters: Clusters across all of them.
    :param services_total: Services in the snapshot.
    :param services_up: ...of which reachable.
    :param services_down: ...of which not.
    :param by_process_role: Service counts per process role.
    """

    environments: int = 0
    clusters: int = 0
    services_total: int = 0
    services_up: int = 0
    services_down: int = 0
    by_process_role: dict[str, int] = Field(default_factory=dict)


class TopologyResponse(BaseModel):
    """The whole topology document plus the provenance of the run behind it.

    :param snapshot: Which run produced this, when, and whether it is stale.
    :param origin_node: The PMM node the snapshot was taken from.
    :param source_queries: The VictoriaMetrics queries the document was derived from.
    :param summary: Fleet-level counts.
    :param environments: The estate, grouped environment then cluster.
    """

    snapshot: SnapshotEnvelope
    origin_node: str | None = None
    source_queries: list[str] = Field(default_factory=list)
    summary: TopologySummary = Field(default_factory=TopologySummary)
    environments: list[TopologyEnvironment] = Field(default_factory=list)


class RunCounts(BaseModel):
    """Count what one discovery run mapped and probed.

    ``services_resolved`` versus ``probes_ok`` is the diagnostic split: the first
    says the executor mapping worked, the second says the node answered. A run with
    ``resolved=9, probes_ok=0`` is a healthy mapping and broken executors.

    :param services_total: MongoDB services inventory reported.
    :param services_resolved: …of which mapped to a live executor host.
    :param services_orphaned: …of which did not. Not an error.
    :param probes_ok: Services that returned a usable probe record.
    """

    services_total: int
    services_resolved: int
    services_orphaned: int
    probes_ok: int


class RunError(BaseModel):
    """Describe one thing that went wrong during a run.

    :param scope: What the error is about, e.g. ``service`` or ``run``.
    :param service_name: The service it concerns, when scoped to one.
    :param code: A machine-readable cause.
    :param message: The human-readable detail.
    """

    scope: str
    service_name: str | None = None
    code: str
    message: str


class DiscoveryRunResponse(BaseModel):
    """Return one discovery run's status, counts and errors.

    :param run_id: The run's id, also the snapshot key and the metrics label.
    :param status: ``running`` / ``success`` / ``partial`` / ``failed``.
    :param started_at: When the run began.
    :param finished_at: When it reached a terminal status; ``None`` while running.
    :param counts: What it mapped and probed.
    :param errors: Per-service and run-level failures.
    """

    run_id: UUID
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    counts: RunCounts
    errors: list[RunError] = Field(default_factory=list)


class DiscoveryRunAccepted(BaseModel):
    """Acknowledge a queued discovery run.

    Returned with ``202``: discovery takes tens of seconds and is never performed
    synchronously. The ``run_id`` is usable immediately -- poll
    ``GET /discovery/runs/{run_id}`` for its status.

    :param run_id: The queued run's id.
    :param status: Always ``running`` at this point.
    :param started_at: When the run row was created.
    """

    run_id: UUID
    status: str
    started_at: datetime
