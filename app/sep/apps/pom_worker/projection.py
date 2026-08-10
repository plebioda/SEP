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

"""Fold a run's per-service rows into one status document per cluster.

This is the worker's last step and the API's whole input: the frontend asks for
clusters, so the clusters are assembled once here rather than rebuilt from flat rows
on every request.

Pure by construction — it takes plain node records and returns plain dicts, so it is
testable without a database, an HTTP client, or a running SEP. The shape it produces
is the topology contract ``pom_api`` serves almost verbatim.

Three rules the shape enforces, all of them corrections to the naive version:

* **A service in inventory with no live exporter is `unknown`, not down.** Absence of
  evidence is recorded as such; 17 of 18 services are in that state in the sandbox,
  and reporting them as healthy or as critical would both be lies.
* **Every null carries a reason.** `unavailable` maps a null field to a
  machine-readable cause, so "we do not know" stays distinguishable from "it is zero".
* **Cluster ids are opaque and server-issued.** `cluster` is a label, not a key — two
  generations of members share the value `sharded-cluster` here — so the id is
  derived from the natural key and the parts are exposed as attributes.
"""

import hashlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

#: Schema version of the emitted document. Bump when the shape changes
#: incompatibly so the API can refuse or migrate an old snapshot.
#: 2 -- ``mongod_running`` became ``server_running`` + ``server_process``, so a
#: router running mongos is no longer reported as a dead node.
SCHEMA_VERSION = 2

#: Ports the sandbox (and the PSMDB convention) uses per role. Only consulted when
#: the probe did not report ``sharding.clusterRole``, which is the case for every
#: service that could not be reached.
CONFIG_SERVER_PORT = 27019
SHARD_SERVER_PORT = 27018

#: ``unavailable`` reasons. Kept as constants because the frontend matches on them.
REASON_NOT_OBSERVED = "service_not_observed"
REASON_METRIC_NOT_COLLECTED = "metric_not_collected"
REASON_NO_VERSION_CATALOG = "no_version_catalog"

#: Health states, worst first — the order `_worst` folds over.
HEALTH_CRITICAL = "critical"
HEALTH_WARNING = "warning"
HEALTH_UNKNOWN = "unknown"
HEALTH_OK = "ok"
_HEALTH_ORDER = (HEALTH_CRITICAL, HEALTH_WARNING, HEALTH_UNKNOWN, HEALTH_OK)

CLUSTER_TYPE_SHARDED = "sharded_cluster"
CLUSTER_TYPE_REPLICA_SET = "replica_set"
CLUSTER_TYPE_STANDALONE = "standalone"

#: ``replSetGetStatus.myState`` values worth naming.
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


@dataclass(frozen=True, slots=True)
class NodeRecord:
    """One service's mapping outcome and probe result, as projection input.

    Deliberately not the SQLModel row: keeping this a plain frozen dataclass is what
    lets the projection be tested without a database.

    :param service_name: The inventory service name.
    :param service_id: The inventory service id.
    :param cluster: The service's cluster label.
    :param replication_set: The service's replica set; empty for a mongos.
    :param environment: The service's environment label.
    :param port: The service port, used to infer a sharded role when unobserved.
    :param executor_host: The resolved executor host, or ``None`` when orphaned.
    :param resolution: How the executor was matched, or that it was not.
    :param probe_status: Whether the probe returned a usable record.
    :param probe: The probe record, when one came back.
    """

    service_name: str
    service_id: int | None
    cluster: str | None
    replication_set: str | None
    environment: str | None
    port: int | None
    executor_host: str | None
    resolution: str
    probe_status: str
    probe: dict[str, Any] | None

    @property
    def observed(self) -> bool:
        """Return whether this service produced a usable probe record.

        :return: ``True`` when the node answered.
        """
        return self.probe_status == "ok" and bool(self.probe)


def cluster_id(
    environment: str | None, cluster: str | None, replication_set: str | None
) -> str:
    """Return a stable opaque id for one cluster entity.

    Derived from the natural key rather than stored, so it is identical across runs
    without a registry table, and it changes only when the key changes. The frontend
    must treat it as opaque and never construct one.

    :param environment: The environment label.
    :param cluster: The cluster label.
    :param replication_set: The replica set, or ``None`` for a sharded cluster.
    :return: The opaque cluster id, ``cl_`` followed by 8 hex characters.
    """
    key = "\x1f".join((environment or "", cluster or "", replication_set or ""))
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"cl_{digest[:8]}"


def member_state_name(state: int | None) -> str | None:
    """Return the name of a ``replSetGetStatus.myState`` value.

    :param state: The numeric member state, or ``None``.
    :return: The state name, ``STATE_<n>`` for an unrecognised value, or ``None`` when
        no state was reported -- a mongos and a standalone both report none.
    """
    if state is None:
        return None
    return _MEMBER_STATES.get(state, f"STATE_{state}")


def _member_state(record: NodeRecord) -> str | None:
    """Return a member's replica-set state name, when the probe reported one.

    :param record: The node record.
    :return: The state name, or ``None`` when unobserved or not in a replica set.
    """
    database = (record.probe or {}).get("database") or {}
    return member_state_name(database.get("state"))


def _sharded_role(record: NodeRecord) -> str:
    """Return a service's role within a sharded cluster.

    Prefers the probe's ``sharding.clusterRole``; falls back to the port convention,
    which is all that is available for a service that could not be reached — and
    unobserved services are the majority, so the fallback is the common path rather
    than an edge case.

    :param record: The node record.
    :return: One of ``config``, ``shard`` or ``mongos``.
    """
    parsed = (
        ((record.probe or {}).get("database") or {})
        .get("raw", {})
        .get("cmd_line_opts", {})
        .get("parsed", {})
    )
    role = (parsed.get("sharding") or {}).get("clusterRole")
    if role == "configsvr":
        return "config"
    if role == "shardsvr":
        return "shard"
    if record.port == CONFIG_SERVER_PORT:
        return "config"
    if record.port == SHARD_SERVER_PORT:
        return "shard"
    return "mongos"


def _worst(statuses: list[str]) -> str:
    """Return the worst status in ``statuses``.

    :param statuses: The statuses to fold.
    :return: The worst, or ``unknown`` when empty.
    """
    for candidate in _HEALTH_ORDER:
        if candidate in statuses:
            return candidate
    return HEALTH_UNKNOWN


def _member_document(record: NodeRecord, *, sharded: bool) -> dict[str, Any]:
    """Build one member entry.

    :param record: The node record.
    :param sharded: Whether the owning cluster is sharded, which adds ``role``.
    :return: The member document.
    """
    database = (record.probe or {}).get("database") or {}
    system = (record.probe or {}).get("system") or {}
    process = (record.probe or {}).get("process") or {}
    member: dict[str, Any] = {
        "service_name": record.service_name,
        "service_id": record.service_id,
        "replication_set": record.replication_set,
        "port": record.port,
        "observed": record.observed,
        "executor_host": record.executor_host,
        "state": _member_state(record),
        "running_version": database.get("db_version"),
        "installed_version": (record.probe or {}).get("binary_version"),
        "os": system.get("os_name"),
        # Role-neutral on purpose: a router runs ``mongos`` and never a mongod, so
        # a field called ``mongod_running`` was false on every healthy router.
        "server_running": process.get("running"),
        "server_process": process.get("program"),
        "uptime_seconds": process.get("uptime_sec"),
    }
    if sharded:
        member["role"] = _sharded_role(record)
    if not record.observed:
        member["unavailable"] = {
            "state": REASON_NOT_OBSERVED,
            "running_version": REASON_NOT_OBSERVED,
            "installed_version": REASON_NOT_OBSERVED,
        }
    return member


def _health(members: list[dict[str, Any]], observed_at: str | None) -> dict[str, Any]:
    """Derive a cluster's health from its members.

    Conservative on purpose. Only two verdicts are currently derivable from what the
    worker collects — everything observed and up, or nothing observed at all — so a
    partially-observed cluster is ``warning`` rather than a guess in either direction.
    Lag- and metric-based rules belong here once the collectors that would feed them
    exist (see §7 of the API plan).

    :param members: The cluster's member documents.
    :param observed_at: When the observation was taken, or ``None``.
    :return: The health block.
    """
    total = len(members)
    observed = sum(1 for member in members if member["observed"])
    reasons: list[dict[str, Any]] = []

    if total and observed == 0:
        reasons.append(
            {
                "code": "no_recent_observation",
                "message": (
                    f"{total} of {total} services have no live executor or did not "
                    "answer; their state is unknown"
                ),
                "severity": HEALTH_UNKNOWN,
            }
        )
        status = HEALTH_UNKNOWN
    elif observed < total:
        reasons.append(
            {
                "code": "partially_observed",
                "message": f"{total - observed} of {total} services were not observed",
                "severity": HEALTH_WARNING,
            }
        )
        status = HEALTH_WARNING
    else:
        status = HEALTH_OK

    down = [
        m["service_name"]
        for m in members
        if m["observed"] and m.get("server_running") is False
    ]
    if down:
        reasons.append(
            {
                "code": "server_not_running",
                # Neither binary is named, because which one a member should run
                # depends on its role and a member that answers nothing cannot say.
                "message": (
                    "no mongod or mongos process is running on "
                    f"{', '.join(sorted(down))}"
                ),
                "severity": HEALTH_CRITICAL,
            }
        )
        status = _worst([status, HEALTH_CRITICAL])

    return {
        "status": status,
        "reasons": reasons,
        "observed_at": observed_at,
        "stale": observed == 0,
    }


def _versions(members: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Summarise the versions across a cluster's observed members.

    :param members: The member documents.
    :return: The versions block and any ``unavailable`` entries it implies.
    """
    running = sorted(
        {m["running_version"] for m in members if m.get("running_version")}
    )
    installed = sorted(
        {m["installed_version"] for m in members if m.get("installed_version")}
    )
    if not running and not installed:
        return (
            {"running": [], "installed": [], "mixed": None, "restart_pending": None},
            {"versions": REASON_NOT_OBSERVED},
        )
    return (
        {
            "running": running,
            "installed": installed,
            "mixed": len(running) > 1,
            # installed != running is the upgraded-but-not-restarted case.
            "restart_pending": bool(installed)
            and bool(running)
            and installed != running,
        },
        {},
    )


def _classify(records: list[NodeRecord]) -> str:
    """Return the topology type for one cluster label's services.

    :param records: Every service carrying that cluster label.
    :return: The cluster type.
    """
    replica_sets = {r.replication_set for r in records if r.replication_set}
    has_mongos = any(not r.replication_set for r in records)
    if len(replica_sets) > 1 or (has_mongos and replica_sets):
        return CLUSTER_TYPE_SHARDED
    if replica_sets:
        return CLUSTER_TYPE_REPLICA_SET
    return CLUSTER_TYPE_STANDALONE


def build_cluster_documents(
    records: list[NodeRecord], generated_at: datetime
) -> list[dict[str, Any]]:
    """Fold a run's node records into one status document per cluster.

    Services are grouped by their ``cluster`` label; a label whose members span
    several replica sets, or that carries a mongos, becomes one **sharded cluster**
    entity rather than several. That is what makes the sandbox's `sharded-cluster` —
    two generations of members under one label — a single entity with a null
    ``replication_set``, matching the API contract.

    :param records: Every service in the run, observed or not.
    :param generated_at: When the snapshot was built.
    :return: One document per cluster, ordered by name.
    """
    by_cluster: dict[str | None, list[NodeRecord]] = {}
    for record in records:
        by_cluster.setdefault(record.cluster, []).append(record)

    documents = []
    for cluster, group in sorted(by_cluster.items(), key=lambda item: item[0] or ""):
        documents.append(_cluster_document(cluster, group, generated_at))
    return documents


def _cluster_document(
    cluster: str | None, records: list[NodeRecord], generated_at: datetime
) -> dict[str, Any]:
    """Build one cluster's status document.

    :param cluster: The cluster label.
    :param records: The services carrying it.
    :param generated_at: When the snapshot was built.
    :return: The cluster document.
    """
    kind = _classify(records)
    environment = next((r.environment for r in records if r.environment), None)
    replication_set = (
        records[0].replication_set if kind != CLUSTER_TYPE_SHARDED else None
    )
    sharded = kind == CLUSTER_TYPE_SHARDED

    members = [_member_document(r, sharded=sharded) for r in records]
    members.sort(key=lambda m: m["service_name"])
    observed = [m for m in members if m["observed"]]
    observed_at = generated_at.isoformat() if observed else None

    versions, version_unavailable = _versions(members)
    unavailable: dict[str, str] = dict(version_unavailable)
    # Neither is derivable from what the worker collects today; see §7 of the API
    # plan for what would close each.
    unavailable["max_replication_lag_seconds"] = (
        REASON_METRIC_NOT_COLLECTED if observed else REASON_NOT_OBSERVED
    )
    unavailable["oplog_window_seconds"] = (
        REASON_METRIC_NOT_COLLECTED if observed else REASON_NOT_OBSERVED
    )

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": cluster_id(environment, cluster, replication_set),
        "name": cluster or "(unnamed)",
        "type": kind,
        "environment": environment,
        "cluster": cluster,
        "replication_set": replication_set,
        "health": _health(members, observed_at),
        "members_total": len(members),
        "members_observed": len(observed),
        "members_by_state": dict(Counter(m["state"] for m in observed if m["state"])),
        "versions": versions,
        "max_replication_lag_seconds": None,
        "oplog_window_seconds": None,
        "last_seen": observed_at,
        "update": {"available": None, "reason": REASON_NO_VERSION_CATALOG},
        "unavailable": unavailable,
        "members": members,
    }

    if sharded:
        roles = Counter(m.get("role") for m in members)
        document["shards"] = len(
            {m["replication_set"] for m in members if m.get("role") == "shard"}
        )
        document["mongos"] = roles.get("mongos", 0)
        document["config_servers"] = roles.get("config", 0)

    return document


def build_summary(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the fleet-level summary the list endpoint returns alongside clusters.

    ``services_unobserved`` is the honest headline number and is deliberately a
    first-class field rather than something the UI derives.

    :param documents: The cluster documents in the snapshot.
    :return: The summary block.
    """
    services_total = sum(doc["members_total"] for doc in documents)
    services_observed = sum(doc["members_observed"] for doc in documents)
    return {
        "clusters": len(documents),
        "by_health": dict(Counter(doc["health"]["status"] for doc in documents)),
        "by_type": dict(Counter(doc["type"] for doc in documents)),
        "services_total": services_total,
        "services_observed": services_observed,
        "services_unobserved": services_total - services_observed,
    }
