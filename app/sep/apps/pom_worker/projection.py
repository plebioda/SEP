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
from dataclasses import field as dataclass_field
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

#: A replica set needs at least this many members for any of them to report lag:
#: lag is measured against the primary's optime, so a lone member has no peer.
_MIN_LAG_MEMBERS = 2

#: ``unavailable`` reasons. Kept as constants because the frontend matches on them.
REASON_NOT_OBSERVED = "service_not_observed"
REASON_METRIC_NOT_COLLECTED = "metric_not_collected"
REASON_NO_VERSION_CATALOG = "no_version_catalog"
#: The topology cannot have this field at all -- a standalone or a router has no
#: replica-set oplog, and a single-member replica set has no secondary to lag. Distinct
#: from ``metric_not_collected``, which means the field *should* exist and did not
#: arrive: one is a fact about the estate, the other a gap in collection.
REASON_NOT_APPLICABLE = "not_applicable"

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
    :param facts: The run's merged facts for this service, in the *serialised* shape
        ``{field: {"value": …, "source": …, "observed_at": …}}`` -- not
        ``{field: value}``. The provenance is kept rather than flattened because health
        rules need to know whether a reading is four seconds or four days old, and
        because :attr:`metrics_observed` is derived from the ``source`` key.
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
    facts: dict[str, Any] = dataclass_field(default_factory=dict)

    @property
    def observed(self) -> bool:
        """Return whether this service produced a usable **probe** record.

        Note the narrowness: this says nothing about metrics coverage. A service that
        VictoriaMetrics describes perfectly well but Nomad cannot reach is *not*
        ``observed`` -- and at fleet scale that is the majority. Use
        :attr:`metrics_observed` when the question is "did we see this at all".

        :return: ``True`` when the node answered a probe.
        """
        return self.probe_status == "ok" and bool(self.probe)

    @property
    def metrics_observed(self) -> bool:
        """Return whether any merged fact for this service came from VictoriaMetrics.

        :return: ``True`` when the metrics source covered this service.
        """
        return any(
            isinstance(entry, dict) and entry.get("source") == "metrics"
            for entry in self.facts.values()
        )


def _fact(record: NodeRecord, name: str) -> Any:
    """Return one merged fact's value, or ``None`` when the run did not observe it.

    :param record: The node record.
    :param name: The fact's field name.
    :return: The value, or ``None``.
    """
    entry = record.facts.get(name)
    return entry.get("value") if isinstance(entry, dict) else None


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


def _has_oplog(record: NodeRecord) -> bool:
    """Return whether this member can have an oplog at all.

    Only a replica-set member does. A standalone and a mongos router both carry no
    ``replication_set``, which is exactly the two cases that have no oplog -- so the one
    check covers both.

    :param record: The node record.
    :return: ``True`` when an oplog window is meaningful for this member.
    """
    return bool(record.replication_set)


def _has_lag(record: NodeRecord, replica_set_sizes: dict[str, int]) -> bool:
    """Return whether this member can report replication lag.

    Needs an oplog *and* a peer to lag behind: the exporter derives lag against the
    primary's optime, so a single-member replica set emits no lag series at all. That
    is *not applicable*, not a collection gap.

    :param record: The node record.
    :param replica_set_sizes: Member counts per replica set within the cluster.
    :return: ``True`` when a lag reading is meaningful for this member.
    """
    if not _has_oplog(record):
        return False
    return replica_set_sizes.get(record.replication_set or "", 0) >= _MIN_LAG_MEMBERS


def _replication_reason(*, metrics_observed: bool, applicable: bool) -> str:
    """Return why a replication field is null.

    Order matters and is deliberate: "we saw nothing of this service" outranks "this
    topology cannot have the field", because an unobserved service's topology claim
    rests on inventory alone and the honest answer is that we do not know.

    :param metrics_observed: Whether VictoriaMetrics covered the subject at all.
    :param applicable: Whether the topology can carry the field.
    :return: The reason code.
    """
    if not metrics_observed:
        return REASON_NOT_OBSERVED
    if not applicable:
        return REASON_NOT_APPLICABLE
    return REASON_METRIC_NOT_COLLECTED


def _oplog_window(record: NodeRecord) -> float | None:
    """Return one member's oplog window in seconds.

    ``head`` and ``tail`` come from the same scrape, so subtracting two separately
    queried values is safe in practice -- their ages differ by tens of milliseconds. The
    ``head >= tail`` guard still rejects the pathological case (mismatched scrapes, clock
    skew) as *unknown* rather than surfacing a negative duration, which the frontend's
    duration formatter renders as a blank cell rather than an em-dash.

    :param record: The node record.
    :return: The window in seconds, or ``None`` when it cannot be computed.
    """
    head = _fact(record, "oplog_head_timestamp")
    tail = _fact(record, "oplog_tail_timestamp")
    if head is None or tail is None or head < tail:
        return None
    return head - tail


def _member_document(
    record: NodeRecord, *, sharded: bool, replica_set_sizes: dict[str, int]
) -> dict[str, Any]:
    """Build one member entry.

    :param record: The node record.
    :param sharded: Whether the owning cluster is sharded, which adds ``role``.
    :param replica_set_sizes: Member counts per replica set, for lag applicability.
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
        "replication_lag_seconds": _fact(record, "replication_lag_seconds"),
        "oplog_window_seconds": _oplog_window(record),
    }
    if sharded:
        member["role"] = _sharded_role(record)

    unavailable: dict[str, str] = {}
    if not record.observed:
        unavailable.update(
            {
                "state": REASON_NOT_OBSERVED,
                "running_version": REASON_NOT_OBSERVED,
                "installed_version": REASON_NOT_OBSERVED,
            }
        )
    # Every null carries a reason -- including these two, so the detail page can say
    # *why* a member shows no lag rather than leaving a bare dash.
    for name, applicable in (
        ("replication_lag_seconds", _has_lag(record, replica_set_sizes)),
        ("oplog_window_seconds", _has_oplog(record)),
    ):
        if member[name] is None:
            unavailable[name] = _replication_reason(
                metrics_observed=record.metrics_observed, applicable=applicable
            )
    if unavailable:
        member["unavailable"] = unavailable
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


def _aggregate(members: list[dict[str, Any]], field: str, fold: Any) -> float | None:
    """Fold one numeric member field across a cluster, ignoring nulls.

    A null member value is *absent*, not zero -- folding it in would make an unobserved
    member look like a perfectly-caught-up one under ``max``, and would peg every
    cluster's oplog window to zero under ``min``.

    :param members: The member documents.
    :param field: The field to fold.
    :param fold: :func:`max` or :func:`min`.
    :return: The folded value, or ``None`` when no member reported one.
    """
    values = [m[field] for m in members if m.get(field) is not None]
    return fold(values) if values else None


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

    replica_set_sizes = Counter(r.replication_set for r in records if r.replication_set)
    members = [
        _member_document(r, sharded=sharded, replica_set_sizes=replica_set_sizes)
        for r in records
    ]
    members.sort(key=lambda m: m["service_name"])
    observed = [m for m in members if m["observed"]]
    observed_at = generated_at.isoformat() if observed else None

    versions, version_unavailable = _versions(members)
    unavailable: dict[str, str] = dict(version_unavailable)

    # The two aggregates differ, and the asymmetry is the point: the worst-lagging
    # member is the cluster's exposure, while the *shortest* oplog is the binding
    # constraint on resync and PITR -- a cluster is only as safe as its tightest oplog.
    metrics_observed = any(r.metrics_observed for r in records)
    max_lag = _aggregate(members, "replication_lag_seconds", max)
    min_window = _aggregate(members, "oplog_window_seconds", min)
    for field, value, applicable in (
        (
            "max_replication_lag_seconds",
            max_lag,
            any(_has_lag(r, replica_set_sizes) for r in records),
        ),
        (
            "oplog_window_seconds",
            min_window,
            any(_has_oplog(r) for r in records),
        ),
    ):
        if value is None:
            unavailable[field] = _replication_reason(
                metrics_observed=metrics_observed, applicable=applicable
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
        "max_replication_lag_seconds": max_lag,
        "oplog_window_seconds": min_window,
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
