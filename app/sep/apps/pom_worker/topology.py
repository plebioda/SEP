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

"""Fold a run's per-service facts into one topology document.

The document is the whole deliverable: ``environments -> clusters -> services``, with
every service carrying its identity, version, replica-set state, reachability and load.
``pom_api`` serves it close to verbatim, so the shape here *is* the wire contract.

Pure by construction -- plain records in, plain dicts out -- so the whole shape is
testable without a database, an HTTP client, or a running SEP.

Four rules the shape enforces:

* **A service that inventory knows and metrics never saw is still in the document**, as
  ``status: DOWN``. Dropping it would shrink the estate every time something broke,
  which is precisely backwards.
* **Grouping is by ``environment`` then ``cluster``**, where cluster falls back to the
  replica set and then to :data:`UNSPECIFIED`. Both keys are emitted as ``null`` rather
  than the sentinel, so the document never invents a name.
* **Numeric gauges use ``-1`` for "not measured"**, not ``0`` and not ``null``. Zero CPU
  is a real reading; the sentinel keeps the two apart in a plain numeric column.
* **Nothing is a verdict.** The document reports what was observed. Health rules read
  it; they do not live here.
"""

from collections import Counter
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any

__all__ = [
    "PROCESS_ROLE_CONFIGSVR",
    "PROCESS_ROLE_MONGOD",
    "PROCESS_ROLE_MONGOS",
    "PROCESS_ROLE_SHARDSVR",
    "SCHEMA_VERSION",
    "SOURCE_QUERIES",
    "STATUS_DOWN",
    "STATUS_UP",
    "UNMEASURED",
    "NodeRecord",
    "build_topology_document",
    "member_state_name",
]

#: Schema version of the emitted document. Bump when the shape changes incompatibly.
#: 3 -- the per-cluster status documents became one ``environments`` topology document,
#: matching the shape the standalone topology export produces.
SCHEMA_VERSION = 3

#: Grouping key for a service whose environment or cluster is unset. Internal only: the
#: document emits ``null`` for it, because inventing the string "UNSPECIFIED" as a name
#: would make it indistinguishable from a real environment called that.
UNSPECIFIED = "UNSPECIFIED"

STATUS_UP = "UP"
STATUS_DOWN = "DOWN"

#: Gauge sentinel. ``-1`` rather than ``null`` so the field stays a number for every
#: service, and rather than ``0`` because zero CPU is a legitimate reading.
UNMEASURED = -1

PROCESS_ROLE_MONGOD = "mongod"
PROCESS_ROLE_MONGOS = "mongos"
PROCESS_ROLE_CONFIGSVR = "configsvr"
PROCESS_ROLE_SHARDSVR = "shardsvr"

#: ``cl_role`` values the exporter reports, mapped to the document's ``process_role``.
_CLUSTER_ROLES = {
    "configsvr": PROCESS_ROLE_CONFIGSVR,
    "shardsvr": PROCESS_ROLE_SHARDSVR,
}

#: The VictoriaMetrics queries behind the document, recorded in it so a reader can see
#: what it was derived from without reading this module.
SOURCE_QUERIES = (
    "mongodb_version_info",
    "mongodb_members_self",
    "mongodb_up",
    "mongodb_mongos_sharding_shards_total",
    "mongodb_sys_cpu_idle_ms",
    "mongodb_connections",
    "mongodb_mongod_replset_member_replication_lag",
    "mongodb_mongod_replset_oplog_head_timestamp",
    "mongodb_mongod_replset_oplog_tail_timestamp",
)

#: What each non-obvious field means, carried in the document for the same reason.
SCHEMA_DESCRIPTION = {
    "origin_node": "PMM node name used as the monitoring origin",
    "environments": "list of monitoring environments",
    "clusters": "list of clusters or replica sets",
    "services": "list of monitored services",
    "state": "PRIMARY or SECONDARY",
    "status": (
        "UP when mongodb_up is 1; DOWN when it is 0 or the service is absent from "
        "current metrics"
    ),
    "cpu_usage_percent": (
        "MongoDB process CPU percentage from mongodb_sys_cpu_idle_ms; -1 when "
        "unavailable or DOWN"
    ),
    "connections_free_percent": (
        "Percentage of available MongoDB connections; -1 when unavailable or DOWN"
    ),
    "process_role": "mongod, mongos, configsvr, or shardsvr",
    "replication_lag_seconds": (
        "Seconds this member trails the primary; null on a router, a standalone, or a "
        "single-member replica set"
    ),
    "oplog_window_seconds": (
        "Seconds of history the oplog holds; null where there is no replica-set oplog"
    ),
    "vendor": "MongoDB or Percona",
    "edition": "Community or Enterprise",
}


#: ``replSetGetStatus.myState`` values worth naming. Only the Nomad probe reports the
#: numeric form; the exporter already gives ``member_state`` as a word.
_MEMBER_STATES = {
    0: "STARTUP",
    1: "PRIMARY",
    2: "SECONDARY",
    3: "RECOVERING",
    5: "STARTUP2",
    6: "UNKNOWN",
    7: "ARBITER",
    8: "DOWN",
    9: "ROLLBACK",
    10: "REMOVED",
}


def member_state_name(state: int | None) -> str | None:
    """Return the name of a ``replSetGetStatus.myState`` value.

    :param state: The numeric member state, or ``None``.
    :return: The state name, ``STATE_<n>`` for an unrecognised value, or ``None`` when
        no state was reported -- a mongos and a standalone both report none.
    """
    if state is None:
        return None
    return _MEMBER_STATES.get(state, f"STATE_{state}")


@dataclass(frozen=True, slots=True)
class NodeRecord:
    """One service's inventory identity and merged facts, as document input.

    Deliberately not the SQLModel row: keeping this a plain frozen dataclass is what
    lets the document be built and tested without a database.

    :param service_name: The inventory service name.
    :param external_id: PMM's service UUID, which the document publishes as
        ``service_id`` -- it is the id every other PMM surface uses, where SEP's own
        integer key means nothing outside SEP.
    :param cluster: The service's cluster label, from inventory.
    :param replication_set: The service's replica set, from inventory.
    :param environment: The service's environment label, from inventory.
    :param facts: The run's merged facts, serialised as
        ``{field: {"value", "source", "observed_at"}}``.
    """

    service_name: str
    external_id: str | None = None
    cluster: str | None = None
    replication_set: str | None = None
    environment: str | None = None
    facts: dict[str, Any] = dataclass_field(default_factory=dict)


def _value(facts: dict[str, Any], name: str) -> Any:
    """Return one merged fact's value, or ``None`` when the run did not observe it.

    :param facts: The service's merged facts, in the serialised shape.
    :param name: The field name.
    :return: The value, or ``None``.
    """
    entry = facts.get(name)
    return entry.get("value") if isinstance(entry, dict) else None


def _process_role(facts: dict[str, Any]) -> str:
    """Return a service's process role.

    ``mongodb_mongos_sharding_shards_total`` is emitted only by a router, so its
    presence is the test -- no port-convention guessing. Otherwise the exporter's
    ``cl_role`` names a config or shard server, and anything else is a plain mongod.

    :param facts: The service's merged facts.
    :return: One of the ``PROCESS_ROLE_*`` values.
    """
    if _value(facts, "is_mongos"):
        return PROCESS_ROLE_MONGOS
    return _CLUSTER_ROLES.get(_value(facts, "cluster_role"), PROCESS_ROLE_MONGOD)


def _gauge(facts: dict[str, Any], name: str, *, up: bool) -> float | int:
    """Return a gauge reading, or :data:`UNMEASURED` when there is none.

    A DOWN service reports the sentinel even if a stale reading survives in the
    collector's window: a CPU figure for a process that is not running would be read as
    current, and a number nobody can act on is worse than an explicit "not measured".

    :param facts: The service's merged facts.
    :param name: The gauge's field name.
    :param up: Whether the service is reachable.
    :return: The reading, or :data:`UNMEASURED`.
    """
    if not up:
        return UNMEASURED
    value = _value(facts, name)
    return UNMEASURED if value is None else value


def _oplog_window(facts: dict[str, Any]) -> float | None:
    """Return the oplog window in seconds, or ``None`` when it cannot be computed.

    ``head`` and ``tail`` come from the same scrape, so subtracting two separately
    queried values is safe in practice. The ``head >= tail`` guard still rejects the
    pathological case -- mismatched scrapes, clock skew -- as unknown rather than
    surfacing a negative duration.

    :param facts: The service's merged facts.
    :return: The window, or ``None``.
    """
    head = _value(facts, "oplog_head_timestamp")
    tail = _value(facts, "oplog_tail_timestamp")
    if head is None or tail is None or head < tail:
        return None
    return head - tail


def _service_document(record: Any) -> dict[str, Any]:
    """Build one service entry.

    :param record: The node record, carrying inventory identity and merged facts.
    :return: The service document.
    """
    facts = record.facts or {}
    up = _value(facts, "exporter_up") == 1
    return {
        "service_name": record.service_name,
        # The inventory service name doubles as the host: PMM registers a sidecar
        # deployment's node under the database container's name, so they agree.
        "host": _value(facts, "host") or record.service_name,
        "endpoint": _value(facts, "endpoint"),
        "service_id": record.external_id,
        "service_type": _value(facts, "service_type") or "mongodb",
        "version": _value(facts, "version"),
        "vendor": _value(facts, "vendor"),
        "edition": _value(facts, "edition"),
        "replication_set": _value(facts, "replication_set") or record.replication_set,
        "state": _value(facts, "state"),
        "status": STATUS_UP if up else STATUS_DOWN,
        "cpu_usage_percent": _gauge(facts, "cpu_usage_percent", up=up),
        "connections_free_percent": _gauge(facts, "connections_free_percent", up=up),
        "process_role": _process_role(facts),
        "replication_lag_seconds": _value(facts, "replication_lag_seconds"),
        "oplog_window_seconds": _oplog_window(facts),
    }


def _grouping_keys(record: Any) -> tuple[str, str]:
    """Return the ``(environment, cluster)`` keys a service groups under.

    Cluster falls back to the replica set, because a replica set registered without a
    ``--cluster=`` string is still a cluster and would otherwise land in one anonymous
    bucket with everything else.

    :param record: The node record.
    :return: The environment and cluster keys.
    """
    facts = record.facts or {}
    environment = _value(facts, "environment") or record.environment or UNSPECIFIED
    cluster = (
        _value(facts, "cluster")
        or record.cluster
        or _value(facts, "replication_set")
        or record.replication_set
        or UNSPECIFIED
    )
    return environment, cluster


def _named(key: str) -> str | None:
    """Return a grouping key as the document spells it.

    :param key: The internal grouping key.
    :return: The name, or ``None`` for :data:`UNSPECIFIED`.
    """
    return None if key == UNSPECIFIED else key


def build_topology_document(
    records: list[Any], generated_at: datetime, origin_node: str | None = None
) -> dict[str, Any]:
    """Fold a run's node records into the topology document.

    :param records: Every service in the run, reachable or not.
    :param generated_at: When the snapshot was built.
    :param origin_node: The PMM node the snapshot was taken from.
    :return: The document.
    """
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for record in records:
        environment, cluster = _grouping_keys(record)
        grouped.setdefault(environment, {}).setdefault(cluster, []).append(
            _service_document(record)
        )

    environments = [
        {
            "env_name": _named(environment),
            "clusters": [
                {
                    "name": _named(cluster),
                    "services": sorted(
                        services, key=lambda service: service["service_name"]
                    ),
                }
                for cluster, services in sorted(clusters.items())
            ],
        }
        for environment, clusters in sorted(grouped.items())
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at.isoformat(),
        "origin_node": origin_node,
        "source_queries": list(SOURCE_QUERIES),
        "schema": dict(SCHEMA_DESCRIPTION),
        "summary": build_summary(environments),
        "environments": environments,
    }


def iter_services(environments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return every service in a document, flattened.

    :param environments: The document's ``environments`` list.
    :return: The service entries.
    """
    return [
        service
        for environment in environments
        for cluster in environment["clusters"]
        for service in cluster["services"]
    ]


def build_summary(environments: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the fleet-level counts the list view shows above the table.

    ``services_down`` is the honest headline and is a first-class field rather than
    something every caller re-derives.

    :param environments: The document's ``environments`` list.
    :return: The summary block.
    """
    services = iter_services(environments)
    up = sum(1 for service in services if service["status"] == STATUS_UP)
    return {
        "environments": len(environments),
        "clusters": sum(len(environment["clusters"]) for environment in environments),
        "services_total": len(services),
        "services_up": up,
        "services_down": len(services) - up,
        "by_process_role": dict(
            Counter(service["process_role"] for service in services)
        ),
    }
