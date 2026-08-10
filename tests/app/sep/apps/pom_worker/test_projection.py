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

"""Test the cluster projection.

The projection is where an unobserved service could quietly be reported as healthy,
which is the single most damaging thing this pipeline could do: 16 of 18 services in
the live sandbox are unobserved, so a bug that folds "we could not look" into "it is
fine" would describe a broken estate as healthy. Most of what follows pins that
distinction.
"""

from datetime import datetime, UTC

from app.sep.apps.pom_worker.projection import (
    build_cluster_documents,
    build_summary,
    cluster_id,
    CLUSTER_TYPE_REPLICA_SET,
    CLUSTER_TYPE_SHARDED,
    CLUSTER_TYPE_STANDALONE,
    HEALTH_CRITICAL,
    HEALTH_OK,
    HEALTH_UNKNOWN,
    HEALTH_WARNING,
    NodeRecord,
    REASON_METRIC_NOT_COLLECTED,
    REASON_NOT_APPLICABLE,
    REASON_NOT_OBSERVED,
)

GENERATED_AT = datetime(2026, 8, 7, 9, 0, 0, tzinfo=UTC)

#: Members in the three-node replica-set fixture.
REPLICA_MEMBERS = 3
#: Pairs in the fixtures that use two of something (config servers, shards,
#: observed members, unobserved services).
PAIR = 2

#: Expected folds over the replication fixtures below.
MAX_LAG = 9.0
MEMBER_LAG = 3.0
MIN_WINDOW = 500.0
SOLO_WINDOW = 800.0
LAG_ONLY_MEMBER = 7.0


def probe(
    state: int = 1,
    version: str = "7.0.39-21",
    *,
    running: bool = True,
    program: str = "mongod",
) -> dict:
    """Build a probe record shaped like the payload's output.

    :param state: The ``replSetGetStatus`` member state.
    :param version: The version both installed and running.
    :param running: Whether the server process is up.
    :param program: Which server program is running -- ``mongos`` on a router.
    :return: The probe record.
    """
    return {
        "binary_version": version,
        "system": {"os_name": "Ubuntu 24.04.3 LTS"},
        "process": {
            "running": running,
            "program": program if running else None,
            "uptime_sec": 100,
        },
        "database": {"db_version": version, "state": state, "set_name": "rs"},
    }


def node(
    name: str,
    *,
    cluster: str = "c",
    replication_set: str | None = "rs",
    port: int = 27017,
    observed: bool = True,
    facts: dict | None = None,
    **kwargs,
) -> NodeRecord:
    """Build a node record for a projection case.

    :param name: The service name.
    :param cluster: The cluster label.
    :param replication_set: The replica set, or ``None`` for a mongos.
    :param port: The service port.
    :param observed: Whether the probe answered.
    :param facts: Merged facts in the serialised shape; see :func:`metric_facts`.
    :param kwargs: Passed through to :func:`probe` when observed.
    :return: The node record.
    """
    return NodeRecord(
        service_name=name,
        service_id=1,
        cluster=cluster,
        replication_set=replication_set,
        environment="sandbox",
        port=port,
        executor_host=name if observed else None,
        resolution="NAME" if observed else "ORPHANED",
        probe_status="ok" if observed else "skipped",
        probe=probe(**kwargs) if observed else None,
        facts=facts or {},
    )


def metric_facts(**values: float) -> dict:
    """Build merged facts as ``_apply_facts`` serialises them.

    The serialised shape -- ``{field: {"value", "source", "observed_at"}}`` -- is what
    the projection actually receives, and getting it wrong is the likeliest way to make
    these tests pass against code that fails on real rows.

    :param values: Field-to-value pairs, all attributed to the metrics source.
    :return: The serialised facts.
    """
    return {
        field: {"value": value, "source": "metrics", "observed_at": None}
        for field, value in values.items()
    }


class TestClusterId:
    """Cover the opaque cluster id."""

    def test_is_stable_for_the_same_key(self) -> None:
        """The same natural key always yields the same id, across runs."""
        assert cluster_id("sandbox", "c", "rs") == cluster_id("sandbox", "c", "rs")

    def test_differs_per_replication_set(self) -> None:
        """Two replica sets under one cluster label are distinct entities."""
        assert cluster_id("sandbox", "c", "rs0") != cluster_id("sandbox", "c", "rs1")

    def test_differs_per_environment(self) -> None:
        """The same cluster name in two environments is two entities."""
        assert cluster_id("prod", "c", "rs") != cluster_id("dev", "c", "rs")

    def test_is_opaque_and_prefixed(self) -> None:
        """The id carries the documented shape the frontend treats as opaque."""
        value = cluster_id("sandbox", "c", "rs")

        assert value.startswith("cl_")
        assert len(value) == len("cl_") + 8


class TestClassification:
    """Cover which topology type a set of services folds into."""

    def test_single_replica_set_is_a_replica_set(self) -> None:
        """One replica set, several members."""
        docs = build_cluster_documents(
            [node(f"m{i}") for i in range(REPLICA_MEMBERS)], GENERATED_AT
        )

        assert docs[0]["type"] == CLUSTER_TYPE_REPLICA_SET
        assert docs[0]["members_total"] == REPLICA_MEMBERS

    def test_no_replication_set_is_a_standalone(self) -> None:
        """A lone service with no replica set."""
        docs = build_cluster_documents(
            [node("solo", replication_set=None)], GENERATED_AT
        )

        assert docs[0]["type"] == CLUSTER_TYPE_STANDALONE

    def test_several_replica_sets_under_one_label_is_one_sharded_cluster(self) -> None:
        """Members spanning replica sets fold into a single sharded entity.

        This is the live sandbox's shape: two generations of members share the
        ``sharded-cluster`` label. Emitting one entity per replica set would show
        the operator five "clusters" that are really one.
        """
        records = [
            node("cfg0", replication_set="cfg", port=27019),
            node("shard0", replication_set="s0", port=27018),
            node("shard1", replication_set="s1", port=27018),
            node("mongos0", replication_set=None),
        ]

        docs = build_cluster_documents(records, GENERATED_AT)

        assert len(docs) == 1
        assert docs[0]["type"] == CLUSTER_TYPE_SHARDED
        assert docs[0]["replication_set"] is None

    def test_sharded_cluster_counts_roles(self) -> None:
        """Shards, mongos and config servers are counted separately."""
        records = [
            node("cfg0", replication_set="cfg", port=27019),
            node("cfg1", replication_set="cfg", port=27019),
            node("s0a", replication_set="s0", port=27018),
            node("s1a", replication_set="s1", port=27018),
            node("mongos0", replication_set=None),
        ]

        doc = build_cluster_documents(records, GENERATED_AT)[0]

        assert doc["config_servers"] == PAIR
        assert doc["shards"] == PAIR
        assert doc["mongos"] == 1

    def test_role_falls_back_to_port_when_unobserved(self) -> None:
        """An unreachable service still gets a role, inferred from its port.

        Unobserved is the common case, so the fallback is the normal path.
        """
        records = [
            node("cfg0", replication_set="cfg", port=27019, observed=False),
            node("s0a", replication_set="s0", port=27018, observed=False),
            node("mongos0", replication_set=None, observed=False),
        ]

        doc = build_cluster_documents(records, GENERATED_AT)[0]

        assert doc["config_servers"] == 1
        assert doc["shards"] == 1
        assert doc["mongos"] == 1


class TestHealth:
    """Cover the health verdict — the part that must never overstate."""

    def test_all_observed_and_up_is_ok(self) -> None:
        """Everything looked at, everything fine."""
        docs = build_cluster_documents([node("a"), node("b")], GENERATED_AT)

        assert docs[0]["health"]["status"] == HEALTH_OK
        assert docs[0]["health"]["reasons"] == []

    def test_nothing_observed_is_unknown_not_ok_and_not_critical(self) -> None:
        """A cluster nobody could reach is ``unknown``.

        The regression guard. Reporting it ``ok`` hides a real outage; reporting it
        ``critical`` cries wolf over every stale inventory row, of which the sandbox
        has 16.
        """
        records = [node(f"m{i}", observed=False) for i in range(REPLICA_MEMBERS)]

        doc = build_cluster_documents(records, GENERATED_AT)[0]

        assert doc["health"]["status"] == HEALTH_UNKNOWN
        assert doc["health"]["stale"] is True
        assert doc["health"]["observed_at"] is None
        assert [r["code"] for r in doc["health"]["reasons"]] == [
            "no_recent_observation"
        ]

    def test_partial_observation_is_warning(self) -> None:
        """Some reached, some not — neither verdict is honest, so it is a warning."""
        doc = build_cluster_documents(
            [node("a"), node("b", observed=False)], GENERATED_AT
        )[0]

        assert doc["health"]["status"] == HEALTH_WARNING
        assert [r["code"] for r in doc["health"]["reasons"]] == ["partially_observed"]

    def test_server_down_is_critical(self) -> None:
        """An observed node running neither mongod nor mongos is a real outage."""
        doc = build_cluster_documents([node("a", running=False)], GENERATED_AT)[0]

        assert doc["health"]["status"] == HEALTH_CRITICAL
        assert "server_not_running" in {r["code"] for r in doc["health"]["reasons"]}

    def test_a_router_running_mongos_is_not_down(self) -> None:
        """A router runs mongos and never a mongod, so it must not read as down.

        The regression this pins: the probe looked only for a process named
        ``mongod``, so every healthy mongos reported ``running: False`` and turned
        its whole sharded cluster critical.
        """
        doc = build_cluster_documents(
            [node("mongos00", program="mongos")], GENERATED_AT
        )[0]

        assert doc["health"]["status"] == HEALTH_OK
        assert doc["health"]["reasons"] == []
        assert doc["members"][0]["server_process"] == "mongos"
        assert doc["members"][0]["server_running"] is True


class TestUnavailableAndVersions:
    """Cover the null-with-a-reason contract."""

    def test_unobserved_members_carry_a_reason_per_null_field(self) -> None:
        """A null is always accompanied by why it is null."""
        doc = build_cluster_documents([node("a", observed=False)], GENERATED_AT)[0]

        member = doc["members"][0]
        assert member["state"] is None
        assert member["unavailable"]["state"] == REASON_NOT_OBSERVED
        assert doc["unavailable"]["versions"] == REASON_NOT_OBSERVED

    def test_mixed_versions_are_flagged(self) -> None:
        """Two running versions in one cluster set ``mixed``."""
        doc = build_cluster_documents(
            [node("a", version="7.0.1"), node("b", version="7.0.2")], GENERATED_AT
        )[0]

        assert doc["versions"]["running"] == ["7.0.1", "7.0.2"]
        assert doc["versions"]["mixed"] is True

    def test_restart_pending_when_installed_differs_from_running(self) -> None:
        """The upgraded-but-not-restarted case is what this field exists for."""
        record = node("a")
        record.probe["binary_version"] = "7.0.40"
        record.probe["database"]["db_version"] = "7.0.39"

        doc = build_cluster_documents([record], GENERATED_AT)[0]

        assert doc["versions"]["restart_pending"] is True

    def test_member_states_counted_only_for_observed(self) -> None:
        """State counts describe what was seen, not what was assumed."""
        doc = build_cluster_documents(
            [node("a", state=1), node("b", state=2), node("c", observed=False)],
            GENERATED_AT,
        )[0]

        assert doc["members_by_state"] == {"PRIMARY": 1, "SECONDARY": 1}
        assert doc["members_observed"] == PAIR
        assert doc["members_total"] == REPLICA_MEMBERS


class TestSummary:
    """Cover the fleet-level rollup."""

    def test_counts_unobserved_services_as_a_first_class_number(self) -> None:
        """``services_unobserved`` is reported, not left for the UI to derive."""
        docs = build_cluster_documents(
            [node("a"), node("b", observed=False), node("c", observed=False)],
            GENERATED_AT,
        )

        summary = build_summary(docs)

        assert summary["services_total"] == REPLICA_MEMBERS
        assert summary["services_observed"] == 1
        assert summary["services_unobserved"] == PAIR

    def test_groups_by_health_and_type(self) -> None:
        """Both breakdowns come from the documents rather than a second pass."""
        docs = build_cluster_documents(
            [node("a", cluster="x"), node("b", cluster="y", observed=False)],
            GENERATED_AT,
        )

        summary = build_summary(docs)

        assert summary["clusters"] == PAIR
        assert summary["by_health"] == {HEALTH_OK: 1, HEALTH_UNKNOWN: 1}
        assert summary["by_type"] == {CLUSTER_TYPE_REPLICA_SET: PAIR}


class TestReplicationFields:
    """Cover replication lag and the oplog window, per member and per cluster.

    These are the first fields sourced from VictoriaMetrics rather than the probe, so
    they are also the cover for `NodeRecord.facts` reaching the projection at all.
    """

    def test_cluster_lag_is_the_worst_member(self) -> None:
        """The worst-lagging member is the cluster's exposure, so `max` wins."""
        documents = build_cluster_documents(
            [
                node("n0", facts=metric_facts(replication_lag_seconds=0.0)),
                node("n1", facts=metric_facts(replication_lag_seconds=9.0)),
                node("n2", facts=metric_facts(replication_lag_seconds=4.0)),
            ],
            GENERATED_AT,
        )
        assert documents[0]["max_replication_lag_seconds"] == MAX_LAG

    def test_cluster_oplog_window_is_the_tightest_member(self) -> None:
        """A cluster is only as safe as its shortest oplog, so `min` wins."""
        documents = build_cluster_documents(
            [
                node(
                    "n0",
                    facts=metric_facts(
                        oplog_head_timestamp=1500.0, oplog_tail_timestamp=1000.0
                    ),
                ),
                node(
                    "n1",
                    facts=metric_facts(
                        oplog_head_timestamp=1900.0, oplog_tail_timestamp=1000.0
                    ),
                ),
            ],
            GENERATED_AT,
        )
        assert documents[0]["oplog_window_seconds"] == MIN_WINDOW

    def test_zero_lag_is_a_value_not_a_gap(self) -> None:
        """The regression that matters most: an idle replica set reads 0, not "unknown".

        Every guard in this file exists to keep "we do not know" apart from "it is
        zero", and lag is the field where the two are most easily conflated -- a healthy
        idle cluster legitimately reports 0 forever.
        """
        documents = build_cluster_documents(
            [
                node("n0", facts=metric_facts(replication_lag_seconds=0.0)),
                node("n1", facts=metric_facts(replication_lag_seconds=0.0)),
            ],
            GENERATED_AT,
        )
        document = documents[0]
        assert document["max_replication_lag_seconds"] == 0.0
        assert "max_replication_lag_seconds" not in document["unavailable"]

    def test_members_carry_their_own_readings(self) -> None:
        """The detail page shows per-member values, so they must survive projection."""
        documents = build_cluster_documents(
            [
                node(
                    "n0",
                    facts=metric_facts(
                        replication_lag_seconds=3.0,
                        oplog_head_timestamp=1500.0,
                        oplog_tail_timestamp=1000.0,
                    ),
                ),
                node("n1", facts=metric_facts(replication_lag_seconds=1.0)),
            ],
            GENERATED_AT,
        )
        member = documents[0]["members"][0]
        assert member["replication_lag_seconds"] == MEMBER_LAG
        assert member["oplog_window_seconds"] == MIN_WINDOW

    def test_a_negative_window_is_rejected_as_unknown(self) -> None:
        """`head < tail` means mismatched scrapes or clock skew, not a negative window.

        Surfacing the negative would render as a blank cell rather than an em-dash, so
        the null is both more honest and more legible.
        """
        documents = build_cluster_documents(
            [
                node(
                    "n0",
                    facts=metric_facts(
                        oplog_head_timestamp=100.0, oplog_tail_timestamp=900.0
                    ),
                )
            ],
            GENERATED_AT,
        )
        document = documents[0]
        assert document["oplog_window_seconds"] is None
        assert (
            document["unavailable"]["oplog_window_seconds"]
            == REASON_METRIC_NOT_COLLECTED
        )

    def test_nulls_are_ignored_rather_than_folded_in(self) -> None:
        """A member with no reading must not read as a perfectly caught-up one."""
        documents = build_cluster_documents(
            [
                node("n0", facts=metric_facts(replication_lag_seconds=7.0)),
                node("n1", facts=metric_facts(version=1.0)),
            ],
            GENERATED_AT,
        )
        assert documents[0]["max_replication_lag_seconds"] == LAG_ONLY_MEMBER


class TestReplicationReasons:
    """Cover the four reason branches for a null replication field."""

    def test_standalone_is_not_applicable(self) -> None:
        """No replica set, no oplog -- a fact about the estate, not a collection gap."""
        documents = build_cluster_documents(
            [node("s0", replication_set=None, facts=metric_facts(version=1.0))],
            GENERATED_AT,
        )
        unavailable = documents[0]["unavailable"]
        assert documents[0]["type"] == CLUSTER_TYPE_STANDALONE
        assert unavailable["max_replication_lag_seconds"] == REASON_NOT_APPLICABLE
        assert unavailable["oplog_window_seconds"] == REASON_NOT_APPLICABLE

    def test_single_member_replica_set_has_an_oplog_but_no_lag(self) -> None:
        """Lag is measured against the primary's optime, so a lone member has no peer."""
        documents = build_cluster_documents(
            [
                node(
                    "g0",
                    facts=metric_facts(
                        oplog_head_timestamp=900.0, oplog_tail_timestamp=100.0
                    ),
                )
            ],
            GENERATED_AT,
        )
        document = documents[0]
        assert document["oplog_window_seconds"] == SOLO_WINDOW
        assert (
            document["unavailable"]["max_replication_lag_seconds"]
            == REASON_NOT_APPLICABLE
        )
        assert "oplog_window_seconds" not in document["unavailable"]

    def test_a_service_metrics_never_saw_is_not_observed(self) -> None:
        """Absence of evidence outranks a topology claim resting on inventory alone."""
        documents = build_cluster_documents([node("u0", observed=False)], GENERATED_AT)
        unavailable = documents[0]["unavailable"]
        assert unavailable["max_replication_lag_seconds"] == REASON_NOT_OBSERVED
        assert unavailable["oplog_window_seconds"] == REASON_NOT_OBSERVED

    def test_covered_but_missing_is_a_collection_gap(self) -> None:
        """Metrics saw the service; the field simply did not arrive."""
        documents = build_cluster_documents(
            [
                node("n0", facts=metric_facts(version=1.0)),
                node("n1", facts=metric_facts(version=1.0)),
            ],
            GENERATED_AT,
        )
        unavailable = documents[0]["unavailable"]
        assert unavailable["max_replication_lag_seconds"] == REASON_METRIC_NOT_COLLECTED
        assert unavailable["oplog_window_seconds"] == REASON_METRIC_NOT_COLLECTED

    def test_a_mongos_is_not_applicable_for_either(self) -> None:
        """A router has no replica set, so neither field is meaningful for it."""
        documents = build_cluster_documents(
            [
                node(
                    "cfg0",
                    replication_set="cfg",
                    port=27019,
                    facts=metric_facts(version=1.0),
                ),
                node(
                    "shard0",
                    replication_set="sh",
                    port=27018,
                    facts=metric_facts(version=1.0),
                ),
                node("mongos0", replication_set=None, facts=metric_facts(version=1.0)),
            ],
            GENERATED_AT,
        )
        router = next(
            m for m in documents[0]["members"] if m["service_name"] == "mongos0"
        )
        assert router["unavailable"]["oplog_window_seconds"] == REASON_NOT_APPLICABLE
        assert router["unavailable"]["replication_lag_seconds"] == REASON_NOT_APPLICABLE


class TestMetricsObserved:
    """Cover the distinction that keeps a monitored-but-unprobeable service honest."""

    def test_metrics_only_service_is_metrics_observed_but_not_observed(self) -> None:
        """The majority case at fleet scale: VM sees it, Nomad cannot reach it.

        Reusing `observed` for metric reason codes would report `service_not_observed`
        for a service VictoriaMetrics describes perfectly well.
        """
        record = node("n0", observed=False, facts=metric_facts(version=1.0))
        assert not record.observed
        assert record.metrics_observed

    def test_probe_only_service_is_not_metrics_observed(self) -> None:
        """A probe-sourced fact must not be mistaken for metrics coverage."""
        record = node(
            "n0",
            facts={"version": {"value": "7.0", "source": "probe", "observed_at": None}},
        )
        assert record.observed
        assert not record.metrics_observed

    def test_a_record_with_no_facts_is_neither(self) -> None:
        """The default keeps every existing construction of NodeRecord working."""
        assert not node("n0", observed=False).metrics_observed
