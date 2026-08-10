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

"""Declare which VictoriaMetrics series discovery reads, and what each supplies.

This table **is** the configuration. Adding a field to the status document is one
:class:`Signal` entry here; nothing else changes, because
:mod:`~app.sep.apps.pom_worker.metrics_source` groups signals by metric and issues one
query per distinct metric however many signals read from it. Nine signals below cost
**two** HTTP round trips.

Two facts about PMM's mongodb_exporter make this table short, and both were measured
against a live VictoriaMetrics:

* **Every ``mongodb_*`` series carries the full identity label set** -- ``service_id``,
  ``service_name``, ``service_type``, ``node_name``, ``node_id``, ``cluster``,
  ``replication_set``, ``environment``, ``agent_id``, ``machine_id``. So identity is
  free on whatever series you were already fetching.
* **``mongodb_version_info`` is an info metric**: its value is always ``1`` and its
  payload is entirely in three labels -- ``mongodb`` (the running version), ``vendor``
  and ``edition``. It is the only source of ``vendor`` and ``edition`` anywhere; the
  Nomad probe collects neither.

.. warning::
   **Never add a wildcard signal.** ``mongodb_ss_*`` -- serverStatus -- is **6362
   series for a single service**, measured, out of 6046 distinct ``mongodb_*`` metric
   names. A ``mongodb_ss_.*`` matcher is roughly 360000 series across a 38-service
   estate. Health rules that want serverStatus leaves must name them in full,
   one :class:`Signal` each.
"""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "GROUP_IDENTITY",
    "GROUP_RS_STATUS",
    "MEMBERS_SELF",
    "SIGNALS",
    "VERSION_INFO",
    "Label",
    "Signal",
    "Value",
    "by_metric",
    "known_groups",
    "signals_for",
]

#: The exporter's info metric: identity, running version, vendor and edition.
VERSION_INFO = "mongodb_version_info"
#: ``replSetGetStatus`` as seen from the member itself -- its own ``member_state``.
#: The sibling ``mongodb_rs_members_state`` carries one series *per peer* and is what a
#: health rule wants; this one is a single series describing the node being asked.
MEMBERS_SELF = "mongodb_members_self"

#: Seconds a peer trails the primary's optime. **Several series per service** -- one per
#: (reporting node, secondary peer) -- so its signal must carry a reducer.
#:
#: The primary itself appears as a peer in no series: the exporter derives lag against
#: the primary's optime, so it has none by construction. A single-member replica set
#: therefore emits nothing at all, which is *not applicable* rather than *not collected*.
REPLICATION_LAG = "mongodb_mongod_replset_member_replication_lag"
#: Oplog bounds as epoch seconds; their difference is the window. One series per
#: service each, so neither needs a reducer. A standalone emits neither -- no replica
#: set, no oplog.
OPLOG_HEAD = "mongodb_mongod_replset_oplog_head_timestamp"
OPLOG_TAIL = "mongodb_mongod_replset_oplog_tail_timestamp"

#: The exporter's own reachability flag: 1 when it connected to mongod. A service that
#: is down produces **no series at all** rather than a 0, so absence is what the
#: document reads as DOWN.
MONGODB_UP = "mongodb_up"
#: Emitted only by a mongos, so its presence *is* the router test. More reliable than
#: the port convention, which only ever guessed.
MONGOS_SHARDS_TOTAL = "mongodb_mongos_sharding_shards_total"

#: Derived percentages. Neither exists as a series, so both are :attr:`Signal.query`
#: expressions. Both aggregate ``by (service_id)`` rather than by ``service_name``,
#: which is what keeps them joinable: a name resolves to several generations of
#: service ids once anything has been re-registered.
CPU_USAGE = "pom:cpu_usage_percent"
CPU_USAGE_QUERY = (
    "100 * (1 - sum by (service_id) (irate(mongodb_sys_cpu_idle_ms{{{matcher}}}[30s]))"
    " / (1000 * max by (service_id) (mongodb_sys_cpu_num_logical_cores{{{matcher}}})))"
)
CONNECTIONS_FREE = "pom:connections_free_percent"
CONNECTIONS_FREE_QUERY = (
    '100 * max by (service_id) (mongodb_connections{{{matcher},state="available"}})'
    ' / (max by (service_id) (mongodb_connections{{{matcher},state="current"}})'
    ' + max by (service_id) (mongodb_connections{{{matcher},state="available"}}))'
)

#: Signal groups, each independently switchable via ``SEP.POM_WORKER.METRICS_GROUPS``.
GROUP_IDENTITY = "identity"
GROUP_RS_STATUS = "rs_status"
GROUP_REPLICATION = "replication"
GROUP_HEALTH = "health"
GROUP_SHARDING = "sharding"


@dataclass(frozen=True, slots=True)
class Label:
    """Take a signal's value from one of the series' labels.

    The common case here: everything the status document needs is carried as a label,
    and the sample value is only evidence that the series exists at all.

    :param name: The label to read.
    """

    name: str

    # ``value`` is unused here and ``labels`` is unused on Value: the two takers share
    # one signature so the collector can call either without knowing which it holds.
    def extract(self, labels: dict[str, str], value: float) -> Any:  # noqa: ARG002
        """Return the label's value.

        :param labels: The series' labels.
        :param value: The sample value, unused.
        :return: The label value, or ``None`` when the label is absent.
        """
        return labels.get(self.name)


@dataclass(frozen=True, slots=True)
class Value:
    """Take a signal's value from the sample itself.

    Unused by the discovery catalog -- every field the document needs is a label -- and
    present because the health job will need it for lag, oplog windows and counters.

    :param cast: Applied to the raw float, e.g. :class:`int` or :class:`bool`.
    """

    cast: Callable[[float], Any] = float

    def extract(self, labels: dict[str, str], value: float) -> Any:  # noqa: ARG002
        """Return the cast sample value.

        :param labels: The series' labels, unused.
        :param value: The sample value.
        :return: The cast value, or ``None`` when casting fails.
        """
        try:
            return self.cast(value)
        except (TypeError, ValueError):
            return None


@dataclass(frozen=True, slots=True)
class Signal:
    """Map one status-document field onto one VictoriaMetrics series.

    :param field: The document field this fills, e.g. ``version``.
    :param metric: The **bare metric name** to query. Deliberately not a free-form
        PromQL expression: the collector appends a ``{service_id=~"..."}`` matcher
        pinning the query to the live service set, and appending a matcher to an
        arbitrary expression is not generally valid. An arithmetic signal -- an oplog
        window, say -- needs an explicit escape hatch added here first.
    :param take: How to read the value: :class:`Label` or :class:`Value`.
    :param group: The switchable group this belongs to.
    :param query: A PromQL template used **instead of** wrapping ``metric``, for a
        derived value no single series carries -- a CPU percentage, a free-connection
        ratio. It must contain ``{matcher}`` wherever a selector belongs, and it must
        aggregate ``by (service_id)`` so the result still joins back to a service.
        ``metric`` then names the query rather than a series, and is only the grouping
        key. Two consequences, both deliberate: an expression is **value-only**, since
        ``lag()`` has no meaning over an arbitrary expression, so its facts are dated to
        the run rather than to a sample; and it must never be built from user input,
        because it is interpolated into PromQL.
    :param reduce: Folds several series for one service into one fact, e.g. :func:`max`.
        ``None`` keeps the one-series-per-service assumption every other signal relies
        on. Required whenever a metric emits more than one series per service:
        ``merge_facts`` keeps the *first* fact for a ``(service, field)`` pair, so
        without a reducer the document would silently carry an arbitrary series' value.
        That bug is near-invisible on an idle estate, where every series reads the same
        number and the wrong answer looks right.
    """

    field: str
    metric: str
    take: Label | Value
    group: str
    query: str | None = None
    reduce: Callable[[list[Any]], Any] | None = None


#: Exactly the signals the status document requires -- nothing speculative. Between
#: them these two metrics supply nine of its ten service fields; the tenth,
#: ``endpoint``, has no VictoriaMetrics label anywhere and comes from inventory.
SIGNALS: tuple[Signal, ...] = (
    # -- mongodb_version_info: identity, versions, provenance -------------------
    Signal("host", VERSION_INFO, Label("node_name"), GROUP_IDENTITY),
    Signal("service_type", VERSION_INFO, Label("service_type"), GROUP_IDENTITY),
    Signal("cluster", VERSION_INFO, Label("cluster"), GROUP_IDENTITY),
    Signal("replication_set", VERSION_INFO, Label("replication_set"), GROUP_IDENTITY),
    Signal("environment", VERSION_INFO, Label("environment"), GROUP_IDENTITY),
    Signal("version", VERSION_INFO, Label("mongodb"), GROUP_IDENTITY),
    Signal("vendor", VERSION_INFO, Label("vendor"), GROUP_IDENTITY),
    Signal("edition", VERSION_INFO, Label("edition"), GROUP_IDENTITY),
    # -- mongodb_members_self: this node's own replica-set state ----------------
    Signal("state", MEMBERS_SELF, Label("member_state"), GROUP_RS_STATUS),
    # ``member_idx`` is the host:port the replica set itself knows the member by, which
    # is a truer endpoint than inventory's address -- inventory records where PMM
    # reached the agent, not where the member advertises itself. A mongos carries no
    # member_idx, so inventory remains the fallback.
    Signal("endpoint", MEMBERS_SELF, Label("member_idx"), GROUP_RS_STATUS),
    # configsvr / shardsvr, straight from the exporter. Replaces the port-convention
    # guess the projection used to fall back on.
    Signal("cluster_role", MEMBERS_SELF, Label("cl_role"), GROUP_RS_STATUS),
    # -- reachability and load --------------------------------------------------
    Signal("exporter_up", MONGODB_UP, Value(float), GROUP_HEALTH),
    Signal(
        "cpu_usage_percent",
        CPU_USAGE,
        Value(float),
        GROUP_HEALTH,
        query=CPU_USAGE_QUERY,
    ),
    Signal(
        "connections_free_percent",
        CONNECTIONS_FREE,
        Value(float),
        GROUP_HEALTH,
        query=CONNECTIONS_FREE_QUERY,
    ),
    # -- sharding: presence alone identifies a router ---------------------------
    Signal("is_mongos", MONGOS_SHARDS_TOTAL, Value(bool), GROUP_SHARDING),
    # -- replication health: the first Value signals in the catalog -------------
    # ``max`` over every series a service reports: each member reports lag against
    # every secondary, so the worst of them is "the worst lag this node saw", and the
    # cluster's max over its members is "the worst lag anyone saw in this replica set".
    # Double-counting is harmless under max.
    Signal(
        "replication_lag_seconds",
        REPLICATION_LAG,
        Value(float),
        GROUP_REPLICATION,
        reduce=max,
    ),
    # Fetched as two raw values and subtracted in the projection rather than as one
    # PromQL expression: ``Signal.metric`` is a bare metric name by design, because the
    # collector appends its own ``{service_id=~"…"}`` matcher. Keeping the collector to
    # one-signal-one-metric costs two extra round trips and no escape hatch in the
    # query builder.
    Signal("oplog_head_timestamp", OPLOG_HEAD, Value(float), GROUP_REPLICATION),
    Signal("oplog_tail_timestamp", OPLOG_TAIL, Value(float), GROUP_REPLICATION),
)


def known_groups(signals: Sequence[Signal] = SIGNALS) -> set[str]:
    """Return every group named in the catalog.

    :param signals: The catalog to inspect.
    :return: The group names.
    """
    return {signal.group for signal in signals}


def signals_for(
    groups: Iterable[str], signals: Sequence[Signal] = SIGNALS
) -> tuple[Signal, ...]:
    """Return the signals belonging to any of ``groups``, in catalog order.

    :param groups: The enabled group names.
    :param signals: The catalog to filter.
    :return: The enabled signals.
    """
    enabled = set(groups)
    return tuple(signal for signal in signals if signal.group in enabled)


def by_metric(signals: Sequence[Signal]) -> dict[str, tuple[Signal, ...]]:
    """Group signals by the metric they read, preserving catalog order.

    This is what keeps the catalog free to grow: the collector issues one query per
    key of this mapping, not one per signal.

    :param signals: The enabled signals.
    :return: ``{metric_name: signals reading it}``.
    """
    grouped: dict[str, list[Signal]] = {}
    for signal in signals:
        grouped.setdefault(signal.metric, []).append(signal)
    return {metric: tuple(items) for metric, items in grouped.items()}
