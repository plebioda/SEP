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

"""Define the common currency every discovery source deals in.

Discovery reads the same MongoDB estate from three places -- SEP's inventory,
VictoriaMetrics, and a Nomad probe -- and each knows a different, overlapping subset
of the truth. Rather than special-case the sources against each other, every one of
them emits the *same* thing: flat :class:`Fact` records keyed by
``(service, field)``. Adding a fourth source is then implementing one function and
changes nothing downstream.

Merging is by **declared precedence per field** (:data:`DEFAULT_PRECEDENCE`), never by
call order. That is what makes "who wins" a piece of configuration rather than an
accident of which source happened to run last, and it is why every merged field keeps
its :class:`MergedField` provenance: a document that cannot say *where* a version came
from cannot distinguish "the node reports 7.0.39" from "the node reported 7.0.39 nine
days ago and has been unreachable since".

Pure by construction -- no SEP imports, no I/O -- so the whole merge is testable
without a database, an HTTP client, or a running SEP.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import StrEnum
from typing import Any

__all__ = [
    "DEFAULT_PRECEDENCE",
    "PRECEDENCE_DEFAULT_KEY",
    "Fact",
    "MergedField",
    "ServiceKey",
    "SourceResult",
    "SourceStatus",
    "merge_facts",
]

#: The key under which :data:`DEFAULT_PRECEDENCE` holds the fallback ordering used by
#: any field that does not name one of its own.
PRECEDENCE_DEFAULT_KEY = "default"


class SourceStatus(StrEnum):
    """Enumerate how completely one source answered.

    Recorded per source on the run, so a thin document is legible rather than merely
    thin: a snapshot assembled with ``metrics=OK, probe=FAILED`` is still correct about
    every version and honest about reachability.

    :cvar OK: The source answered for every service asked about.
    :cvar PARTIAL: The source answered for some services but not all.
    :cvar FAILED: The source answered for none, or raised.
    :cvar DISABLED: The source was switched off in settings and never ran.
    """

    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class ServiceKey:
    """Identify one MongoDB service across all three sources.

    Three identifiers, because the sources do not agree on one:

    * ``key`` is SEP's own inventory id, stringified. It is the join key every
      :class:`Fact` carries, chosen because ``pom_node`` rows key on it too.
    * ``external_id`` is **PMM's** service UUID (SEP inventory's ``external_id``
      column), which is what VictoriaMetrics carries as its ``service_id`` label.
    * ``name`` is for display and for the executor mapping, which matches on names.

    **Never join on ``name``.** It is not unique over time: every re-registration mints
    fresh PMM UUIDs while reusing the name, and the superseded series live on in
    VictoriaMetrics until retention expires. Measured in this workspace's VM, 38
    distinct ``service_name`` values resolve to 206 distinct ``service_id`` values --
    so a name-filtered query returns roughly five dead generations alongside the live
    one, and taking the first match yields facts about a container that no longer
    exists.

    :param key: SEP's inventory service id as a string; the fact join key.
    :param name: The inventory service name, for display and executor matching.
    :param external_id: PMM's service UUID, or ``None`` when inventory carries none.
    """

    key: str
    name: str
    external_id: str | None = None


@dataclass(frozen=True, slots=True)
class Fact:
    """Carry one field about one service, as one source saw it.

    :param service: The owning :class:`ServiceKey`'s ``key``.
    :param field: The document field this sets, e.g. ``version``.
    :param value: The observed value.
    :param source: The source key that produced it, e.g. ``metrics``.
    :param observed_at: When the underlying observation was taken, or ``None`` for a
        source that is not time-bounded. Inventory is not time-bounded: it is current
        by definition. A metric sample very much is -- see :class:`SourceStatus`.
    """

    service: str
    field: str
    value: Any
    source: str
    observed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SourceResult:
    """Report everything one source produced in one discovery run.

    :param source: The source key.
    :param status: How completely it answered.
    :param facts: Every fact it produced.
    :param detail: Source-specific counters and errors. Lands verbatim in
        ``pom_run.sources``, which is the run's receipt and the document's top-level
        provenance metadata.
    """

    source: str
    status: SourceStatus
    facts: tuple[Fact, ...] = ()
    detail: dict[str, Any] = dataclass_field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MergedField:
    """Hold one field's winning value together with where it came from.

    :param value: The value that won.
    :param source: The source that supplied it.
    :param observed_at: When it was observed, or ``None`` when not time-bounded.
    """

    value: Any
    source: str
    observed_at: datetime | None = None


#: Which source may supply which field, best first. A source **not** listed for a field
#: is not permitted to supply it, which is the point of declaring this rather than
#: letting call order decide.
#:
#: The reasoning behind the non-obvious entries, all of it measured against a live
#: PMM:
#:
#: * ``installed_version`` -- the probe alone can read ``mongod --version``. Metrics
#:   only ever know the *running* version, and the divergence between the two is
#:   precisely the upgraded-but-not-restarted case an upgrade check exists to catch.
#: * ``vendor`` / ``edition`` -- ``mongodb_version_info`` is the only source of either
#:   anywhere. The probe has no such concept.
#: * ``endpoint`` -- no VictoriaMetrics label carries an address and port; inventory is
#:   the only source.
#: * ``state`` -- metrics first because a member's replica-set state as reported through
#:   the exporter covers services the probe cannot reach at all.
DEFAULT_PRECEDENCE: Mapping[str, tuple[str, ...]] = {
    PRECEDENCE_DEFAULT_KEY: ("metrics", "inventory", "probe"),
    "version": ("metrics", "probe"),
    "installed_version": ("probe",),
    "vendor": ("metrics",),
    "edition": ("metrics",),
    # ``member_idx`` is how the replica set itself addresses the member, which beats
    # inventory's record of where PMM reached the agent. Inventory stays the fallback,
    # and is the only source for a mongos, which has no member_idx.
    "endpoint": ("metrics", "inventory"),
    # Replication health. Metrics-only: no other source can supply any of them,
    # and an unlisted source is forbidden from trying.
    "replication_lag_seconds": ("metrics",),
    "oplog_head_timestamp": ("metrics",),
    "oplog_tail_timestamp": ("metrics",),
    # Reachability, load and role, all of them exporter-only concepts.
    "exporter_up": ("metrics",),
    "cpu_usage_percent": ("metrics",),
    "connections_free_percent": ("metrics",),
    "cluster_role": ("metrics",),
    "is_mongos": ("metrics",),
    "state": ("metrics", "probe"),
}


def _is_present(value: Any) -> bool:
    """Return whether a value counts as an observation at all.

    An empty string is treated as absent because Prometheus cannot distinguish the two:
    a label that was never set and a label set to ``""`` are the same series. A mongos
    carries ``replication_set=""`` for exactly this reason, and letting that win over an
    inventory value that actually knows the answer would be a regression.

    ``False`` and ``0`` are emphatically present -- that is the whole "we do not know"
    versus "it is zero" distinction the document turns on.

    :param value: The candidate value.
    :return: ``True`` when the value is a real observation.
    """
    return value is not None and value != ""


def merge_facts(
    results: Iterable[SourceResult],
    precedence: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, dict[str, MergedField]]:
    """Fold every source's facts into one mapping per service, with provenance.

    For each ``(service, field)``, the first source in that field's precedence list that
    supplied a present value wins. A source that is not listed for a field cannot
    supply it however loudly it shouts -- so switching a field's owner is an edit to
    :data:`DEFAULT_PRECEDENCE`, not to a collector.

    :param results: Every source's result for this run.
    :param precedence: Field-to-source-order mapping; defaults to
        :data:`DEFAULT_PRECEDENCE`. Must carry a :data:`PRECEDENCE_DEFAULT_KEY` entry.
    :return: ``{service_key: {field: MergedField}}``.
    """
    table = precedence if precedence is not None else DEFAULT_PRECEDENCE
    fallback = tuple(table.get(PRECEDENCE_DEFAULT_KEY, ()))

    # (service, field) -> source -> fact. A source emitting the same field twice for one
    # service keeps the first; sources are expected not to, and silently preferring the
    # last would hide the bug.
    indexed: dict[tuple[str, str], dict[str, Fact]] = {}
    for result in results:
        for fact in result.facts:
            if not _is_present(fact.value):
                continue
            indexed.setdefault((fact.service, fact.field), {}).setdefault(
                fact.source, fact
            )

    merged: dict[str, dict[str, MergedField]] = {}
    for (service, field), by_source in indexed.items():
        for source in table.get(field, fallback):
            fact = by_source.get(source)
            if fact is None:
                continue
            merged.setdefault(service, {})[field] = MergedField(
                value=fact.value, source=fact.source, observed_at=fact.observed_at
            )
            break

    return merged


def flatten(merged: Mapping[str, MergedField]) -> dict[str, Any]:
    """Return one service's merged fields as a plain ``field: value`` mapping.

    The document carries values at the top level and provenance beside them rather than
    nesting every field in an object, so this is what builds the former.

    :param merged: One service's merged fields.
    :return: The field-to-value mapping.
    """
    return {field: item.value for field, item in merged.items()}


def provenance(merged: Mapping[str, MergedField]) -> dict[str, str]:
    """Return one service's ``field: source`` provenance mapping.

    :param merged: One service's merged fields.
    :return: The field-to-source mapping.
    """
    return {field: item.source for field, item in merged.items()}
