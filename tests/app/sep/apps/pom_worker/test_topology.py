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

"""Test the topology document.

The document is the whole wire contract, so most of what follows pins the two
distinctions it exists to keep: a service that is down versus one nobody looked at, and
a gauge reading of zero versus no reading at all.
"""

from datetime import datetime, UTC

from app.sep.apps.pom_worker.topology import (
    build_topology_document,
    member_state_name,
    NodeRecord,
    PROCESS_ROLE_CONFIGSVR,
    PROCESS_ROLE_MONGOD,
    PROCESS_ROLE_MONGOS,
    PROCESS_ROLE_SHARDSVR,
    SCHEMA_VERSION,
    STATUS_DOWN,
    STATUS_UP,
    UNMEASURED,
)

GENERATED_AT = datetime(2026, 8, 10, 9, 0, 0, tzinfo=UTC)

#: Readings the fixtures assert on.
CPU = 13.5
CONNECTIONS_FREE = 99.9
LAG = 10.0
OPLOG_WINDOW = 500.0
THREE = 3
TWO = 2


def facts(**values) -> dict:
    """Build merged facts as the worker serialises them."""
    return {
        field: {"value": value, "source": "metrics", "observed_at": None}
        for field, value in values.items()
    }


def node(name: str, *, up: bool = True, **overrides) -> NodeRecord:
    """Build a node record with sandbox-shaped defaults."""
    base = {
        "environment": "sandbox",
        "cluster": "replicaset-cluster",
        "replication_set": "replicaset-cluster",
    }
    fact_values = {
        "environment": "sandbox",
        "cluster": "replicaset-cluster",
        "replication_set": "replicaset-cluster",
        "host": name,
        "endpoint": f"{name}:27017",
        "version": "7.0.39-21",
        "vendor": "Percona",
        "edition": "Community",
        "state": "SECONDARY",
        "service_type": "mongodb",
    }
    if up:
        fact_values["exporter_up"] = 1.0
    fact_values.update(overrides.pop("facts", {}))
    # Grouping reads the metrics facts first, so an override has to land in both or
    # the record field would be quietly ignored -- exactly as it is in production.
    for key in ("environment", "cluster", "replication_set"):
        if key in overrides:
            fact_values[key] = overrides[key]
    base.update(overrides)
    return NodeRecord(
        service_name=name,
        external_id=f"uuid-{name}",
        facts=facts(**fact_values),
        **base,
    )


def services(document) -> list[dict]:
    """Flatten every service in a document."""
    return [
        service
        for environment in document["environments"]
        for cluster in environment["clusters"]
        for service in cluster["services"]
    ]


class TestShape:
    """Cover the environments -> clusters -> services nesting."""

    def test_groups_by_environment_then_cluster(self):
        """The document's two levels of nesting are its whole organising idea."""
        document = build_topology_document(
            [
                node("a", environment="PROD", cluster="rs0"),
                node("b", environment="PROD", cluster="rs1"),
                node("c", environment="DEV", cluster="rs0"),
            ],
            GENERATED_AT,
        )
        assert [e["env_name"] for e in document["environments"]] == ["DEV", "PROD"]
        prod = document["environments"][1]
        assert [c["name"] for c in prod["clusters"]] == ["rs0", "rs1"]

    def test_unset_environment_is_null_not_a_sentinel(self):
        """Emitting "UNSPECIFIED" would be indistinguishable from a real name."""
        document = build_topology_document(
            [
                node(
                    "a",
                    environment=None,
                    cluster=None,
                    replication_set=None,
                    facts={
                        "environment": None,
                        "cluster": None,
                        "replication_set": None,
                    },
                )
            ],
            GENERATED_AT,
        )
        assert document["environments"][0]["env_name"] is None
        assert document["environments"][0]["clusters"][0]["name"] is None

    def test_cluster_falls_back_to_the_replica_set(self):
        """A replica set registered without --cluster= is still a cluster."""
        document = build_topology_document(
            [
                node(
                    "a", cluster=None, facts={"cluster": None, "replication_set": "rs9"}
                )
            ],
            GENERATED_AT,
        )
        assert document["environments"][0]["clusters"][0]["name"] == "rs9"

    def test_services_are_sorted_within_a_cluster(self):
        """A stable order keeps the rendered table from reshuffling between runs."""
        document = build_topology_document(
            [node("c"), node("a"), node("b")], GENERATED_AT
        )
        assert [s["service_name"] for s in services(document)] == ["a", "b", "c"]

    def test_carries_its_own_provenance(self):
        """A document moved between environments still says where it came from."""
        document = build_topology_document([node("a")], GENERATED_AT, origin_node="pmm")
        assert document["origin_node"] == "pmm"
        assert document["generated_at"] == GENERATED_AT.isoformat()
        assert document["schema_version"] == SCHEMA_VERSION
        assert "mongodb_version_info" in document["source_queries"]
        assert document["schema"]["state"]

    def test_publishes_the_pmm_service_uuid(self):
        """`service_id` is PMM's UUID; SEP's integer key means nothing outside SEP."""
        document = build_topology_document([node("a")], GENERATED_AT)
        assert services(document)[0]["service_id"] == "uuid-a"


class TestStatusAndGauges:
    """Cover reachability and the -1 sentinel."""

    def test_reachable_service_is_up_with_real_gauges(self):
        """The happy path."""
        document = build_topology_document(
            [
                node(
                    "a",
                    facts={
                        "cpu_usage_percent": CPU,
                        "connections_free_percent": CONNECTIONS_FREE,
                    },
                )
            ],
            GENERATED_AT,
        )
        service = services(document)[0]
        assert service["status"] == STATUS_UP
        assert service["cpu_usage_percent"] == CPU
        assert service["connections_free_percent"] == CONNECTIONS_FREE

    def test_a_service_metrics_never_saw_is_down_not_absent(self):
        """Dropping it would shrink the estate every time something broke."""
        document = build_topology_document([node("a", up=False)], GENERATED_AT)
        service = services(document)[0]
        assert service["status"] == STATUS_DOWN
        assert service["service_name"] == "a"

    def test_a_down_service_reports_unmeasured_gauges(self):
        """A stale CPU figure for a dead process would be read as current."""
        document = build_topology_document(
            [node("a", up=False, facts={"cpu_usage_percent": CPU})], GENERATED_AT
        )
        service = services(document)[0]
        assert service["cpu_usage_percent"] == UNMEASURED
        assert service["connections_free_percent"] == UNMEASURED

    def test_zero_cpu_is_a_reading_not_a_gap(self):
        """Idle is a legitimate answer and must not collapse into the sentinel."""
        document = build_topology_document(
            [node("a", facts={"cpu_usage_percent": 0.0})], GENERATED_AT
        )
        assert services(document)[0]["cpu_usage_percent"] == 0.0

    def test_a_missing_gauge_on_an_up_service_is_unmeasured(self):
        """Up but unreadable is still "we do not know", not zero."""
        document = build_topology_document([node("a")], GENERATED_AT)
        assert services(document)[0]["cpu_usage_percent"] == UNMEASURED


class TestProcessRole:
    """Cover role detection, which no longer guesses from the port."""

    def test_a_router_is_identified_by_its_sharding_metric(self):
        """mongodb_mongos_sharding_shards_total is emitted only by a mongos."""
        document = build_topology_document(
            [node("m", facts={"is_mongos": True})], GENERATED_AT
        )
        assert services(document)[0]["process_role"] == PROCESS_ROLE_MONGOS

    def test_cluster_role_names_config_and_shard_servers(self):
        """cl_role comes straight from the exporter."""
        document = build_topology_document(
            [
                node("cfg", facts={"cluster_role": "configsvr"}),
                node("shard", facts={"cluster_role": "shardsvr"}),
            ],
            GENERATED_AT,
        )
        roles = {s["service_name"]: s["process_role"] for s in services(document)}
        assert roles["cfg"] == PROCESS_ROLE_CONFIGSVR
        assert roles["shard"] == PROCESS_ROLE_SHARDSVR

    def test_anything_else_is_a_plain_mongod(self):
        """The default, and what a replica-set member reports."""
        document = build_topology_document([node("a")], GENERATED_AT)
        assert services(document)[0]["process_role"] == PROCESS_ROLE_MONGOD

    def test_the_router_test_wins_over_cluster_role(self):
        """A router carrying a stale cl_role must still read as a router."""
        document = build_topology_document(
            [node("m", facts={"is_mongos": True, "cluster_role": "shardsvr"})],
            GENERATED_AT,
        )
        assert services(document)[0]["process_role"] == PROCESS_ROLE_MONGOS


class TestReplicationFields:
    """Cover lag and the oplog window, which are null rather than -1 when absent."""

    def test_lag_and_window_are_carried_through(self):
        """Both survive into the service entry."""
        document = build_topology_document(
            [
                node(
                    "a",
                    facts={
                        "replication_lag_seconds": LAG,
                        "oplog_head_timestamp": 1500.0,
                        "oplog_tail_timestamp": 1000.0,
                    },
                )
            ],
            GENERATED_AT,
        )
        service = services(document)[0]
        assert service["replication_lag_seconds"] == LAG
        assert service["oplog_window_seconds"] == OPLOG_WINDOW

    def test_zero_lag_is_a_reading(self):
        """An idle replica set legitimately reports 0 forever."""
        document = build_topology_document(
            [node("a", facts={"replication_lag_seconds": 0.0})], GENERATED_AT
        )
        assert services(document)[0]["replication_lag_seconds"] == 0.0

    def test_absent_lag_is_null_not_the_gauge_sentinel(self):
        """Null means "not a thing here"; -1 would claim a failed measurement."""
        document = build_topology_document([node("a")], GENERATED_AT)
        service = services(document)[0]
        assert service["replication_lag_seconds"] is None
        assert service["oplog_window_seconds"] is None

    def test_a_negative_window_is_rejected(self):
        """Head < tail means mismatched scrapes, not a negative window."""
        document = build_topology_document(
            [
                node(
                    "a",
                    facts={
                        "oplog_head_timestamp": 100.0,
                        "oplog_tail_timestamp": 900.0,
                    },
                )
            ],
            GENERATED_AT,
        )
        assert services(document)[0]["oplog_window_seconds"] is None


class TestSummary:
    """Cover the fleet counts the UI shows above the table."""

    def test_counts_up_and_down(self):
        """services_down is the honest headline, not something the UI re-derives."""
        document = build_topology_document(
            [node("a"), node("b"), node("c", up=False)], GENERATED_AT
        )
        summary = document["summary"]
        assert summary["services_total"] == THREE
        assert summary["services_up"] == TWO
        assert summary["services_down"] == 1

    def test_counts_environments_and_clusters(self):
        """Both nesting levels are counted, not just the leaves."""
        document = build_topology_document(
            [
                node("a", environment="PROD", cluster="rs0"),
                node("b", environment="DEV", cluster="rs1"),
            ],
            GENERATED_AT,
        )
        assert document["summary"]["environments"] == TWO
        assert document["summary"]["clusters"] == TWO

    def test_counts_by_process_role(self):
        """Lets the UI say "2 mongos" without walking the tree."""
        document = build_topology_document(
            [node("m", facts={"is_mongos": True}), node("a")], GENERATED_AT
        )
        assert document["summary"]["by_process_role"] == {"mongos": 1, "mongod": 1}


class TestMemberStateName:
    """Cover the probe's numeric state mapping, still used by the probe source."""

    def test_names_the_common_states(self):
        """1 is PRIMARY, 2 is SECONDARY."""
        assert member_state_name(1) == "PRIMARY"
        assert member_state_name(2) == "SECONDARY"

    def test_none_stays_none(self):
        """A mongos and a standalone both report no state."""
        assert member_state_name(None) is None

    def test_an_unknown_state_is_labelled_not_dropped(self):
        """A future state must still be visible rather than silently blank."""
        assert member_state_name(99) == "STATE_99"
