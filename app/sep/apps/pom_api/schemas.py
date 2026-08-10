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
from typing import Any
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


class HealthSummary(BaseModel):
    """Count clusters and services across the whole snapshot.

    :param clusters: Clusters in the snapshot.
    :param by_health: Cluster counts keyed by health status.
    :param by_type: Cluster counts keyed by topology type.
    :param services_total: Services across every cluster.
    :param services_observed: …of which answered a probe.
    :param services_unobserved: …of which did not. The honest headline number: a
        service in inventory with no live exporter is neither healthy nor down.
    """

    clusters: int
    by_health: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    services_total: int
    services_observed: int
    services_unobserved: int


class GroupCount(BaseModel):
    """Name one grouping bucket for the list view's group headers.

    :param key: The machine value, e.g. ``critical``.
    :param label: The display label, e.g. ``Critical``.
    :param count: Clusters in the bucket.
    """

    key: str
    label: str
    count: int


class ClusterListResponse(BaseModel):
    """Return the cluster list, its summary and its grouping counts.

    ``clusters`` entries are the worker's assembled documents passed through
    verbatim, so the wire shape is whatever the projection wrote. They are typed
    loosely here on purpose: pinning every nested field would duplicate the
    projection's contract in a second place and guarantee the two drift.

    :param generated_at: Snapshot provenance; see :class:`SnapshotEnvelope`.
    :param observed_at: Newest observation in the snapshot.
    :param stale: Whether the snapshot is past its grace period.
    :param schema_version: The document schema version.
    :param run_id: The discovery run this came from.
    :param summary: Fleet-level counts.
    :param groups: Grouping buckets for the current grouping.
    :param clusters: The cluster documents, without their member lists.
    :param next_cursor: Reserved for pagination; always ``None`` today.
    """

    generated_at: datetime
    observed_at: datetime | None = None
    stale: bool = False
    schema_version: int = 1
    run_id: UUID
    summary: HealthSummary
    groups: list[GroupCount] = Field(default_factory=list)
    clusters: list[dict[str, Any]] = Field(default_factory=list)
    next_cursor: str | None = None


class ClusterDetailResponse(BaseModel):
    """Return one cluster's full document, members included.

    :param generated_at: Snapshot provenance.
    :param observed_at: Newest observation in the snapshot.
    :param stale: Whether the snapshot is past its grace period.
    :param schema_version: The document schema version.
    :param run_id: The discovery run this came from.
    :param cluster: The complete cluster document.
    """

    generated_at: datetime
    observed_at: datetime | None = None
    stale: bool = False
    schema_version: int = 1
    run_id: UUID
    cluster: dict[str, Any]


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
