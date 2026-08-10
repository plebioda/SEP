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

"""Test the fact merge: precedence, presence, and provenance.

Pure -- no database, no HTTP client, no SEP fixtures.
"""

from datetime import datetime, UTC

import pytest

from app.sep.apps.pom_worker.fact_sources import inventory_facts, probe_facts
from app.sep.apps.pom_worker.facts import (
    DEFAULT_PRECEDENCE,
    Fact,
    flatten,
    merge_facts,
    provenance,
    SourceResult,
    SourceStatus,
)
from app.sep.apps.pom_worker.inventory import InventoryService

OBSERVED = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)

#: Sandbox-shaped counts, named so assertions read as intent rather than magic.
UNRESOLVED_SOME = 2
UNRESOLVED_ALL = 14

#: The value the replication precedence fixtures assert on.
ACCEPTED_VALUE = 5.0


def _result(source: str, *facts: Fact) -> SourceResult:
    """Build a source result carrying ``facts``."""
    return SourceResult(source, SourceStatus.OK, facts)


def _service(**overrides) -> InventoryService:
    """Build an inventory service with sandbox-shaped defaults."""
    fields = {
        "service_id": 7,
        "external_id": "ff0275b6-3633-474a-8068-3c39d3c7a4da",
        "name": "replicaset-cluster-node00",
        "port": 27017,
        "cluster": "replicaset-cluster",
        "replication_set": "replicaset-cluster",
        "environment": "sandbox",
        "node_name": "replicaset-cluster-node00",
        "node_address": "replicaset-cluster-node00",
    }
    fields.update(overrides)
    return InventoryService(**fields)


class TestMergePrecedence:
    """Cover which source wins which field."""

    def test_metrics_beats_probe_for_version(self):
        """The running version comes from metrics when both sources have one."""
        merged = merge_facts(
            [
                _result("probe", Fact("7", "version", "7.0.14-8", "probe")),
                _result("metrics", Fact("7", "version", "7.0.39-21", "metrics")),
            ]
        )
        assert merged["7"]["version"].value == "7.0.39-21"
        assert merged["7"]["version"].source == "metrics"

    def test_probe_supplies_version_when_metrics_silent(self):
        """The probe is the declared fallback, not an also-ran that never wins."""
        merged = merge_facts(
            [_result("probe", Fact("7", "version", "7.0.14-8", "probe"))]
        )
        assert merged["7"]["version"].source == "probe"

    def test_installed_version_is_probe_only(self):
        """Only the probe can read the installed binary; nothing else may claim it."""
        merged = merge_facts(
            [
                _result("probe", Fact("7", "installed_version", "7.0.39-21", "probe")),
                _result("metrics", Fact("7", "installed_version", "9.9.9", "metrics")),
            ]
        )
        assert merged["7"]["installed_version"].value == "7.0.39-21"

    def test_unlisted_source_cannot_supply_a_restricted_field(self):
        """`vendor` is declared metrics-only, so a probe-sourced vendor is dropped."""
        merged = merge_facts(
            [_result("probe", Fact("7", "vendor", "Percona", "probe"))]
        )
        assert "vendor" not in merged.get("7", {})

    def test_endpoint_prefers_the_replica_sets_own_address(self):
        """Prefer the replica set's own address for the member.

        `member_idx` is how the set addresses the member; inventory records where PMM
        reached the agent, which is not the same thing in a sidecar deployment.
        """
        merged = merge_facts(
            [
                _result("metrics", Fact("7", "endpoint", "mongo1:27017", "metrics")),
                _result(
                    "inventory", Fact("7", "endpoint", "127.0.0.1:27017", "inventory")
                ),
            ]
        )
        assert merged["7"]["endpoint"].value == "mongo1:27017"

    def test_endpoint_falls_back_to_inventory(self):
        """A mongos carries no member_idx, so inventory is all there is."""
        merged = merge_facts(
            [_result("inventory", Fact("7", "endpoint", "mongos:27017", "inventory"))]
        )
        assert merged["7"]["endpoint"].source == "inventory"

    def test_precedence_is_declared_not_call_order(self):
        """Reordering the sources changes nothing; only the table decides."""
        forwards = merge_facts(
            [
                _result("metrics", Fact("7", "state", "PRIMARY", "metrics")),
                _result("probe", Fact("7", "state", "SECONDARY", "probe")),
            ]
        )
        backwards = merge_facts(
            [
                _result("probe", Fact("7", "state", "SECONDARY", "probe")),
                _result("metrics", Fact("7", "state", "PRIMARY", "metrics")),
            ]
        )
        assert (
            forwards["7"]["state"].value == backwards["7"]["state"].value == "PRIMARY"
        )

    def test_custom_precedence_table_is_honoured(self):
        """The table is a parameter, so a caller can invert ownership wholesale."""
        merged = merge_facts(
            [
                _result("metrics", Fact("7", "version", "a", "metrics")),
                _result("probe", Fact("7", "version", "b", "probe")),
            ],
            precedence={"default": ("probe", "metrics")},
        )
        assert merged["7"]["version"].value == "b"


class TestPresence:
    """Cover what counts as an observation."""

    def test_empty_string_is_absent(self):
        """Prometheus cannot distinguish an unset label from `""`; a mongos has both."""
        merged = merge_facts(
            [
                _result("metrics", Fact("7", "replication_set", "", "metrics")),
                _result("inventory", Fact("7", "replication_set", "rs0", "inventory")),
            ]
        )
        assert merged["7"]["replication_set"].value == "rs0"

    def test_none_is_absent(self):
        """A null observation never wins over a real one."""
        merged = merge_facts(
            [
                _result("metrics", Fact("7", "cluster", None, "metrics")),
                _result("inventory", Fact("7", "cluster", "rs0", "inventory")),
            ]
        )
        assert merged["7"]["cluster"].source == "inventory"

    def test_false_is_present(self):
        """`False` is an answer, not a missing one -- the whole point of `unavailable`."""
        merged = merge_facts(
            [
                _result(
                    "probe",
                    Fact("7", "server_running", value=False, source="probe"),
                )
            ]
        )
        assert merged["7"]["server_running"].value is False

    def test_zero_is_present(self):
        """Likewise `0`: "we do not know" and "it is zero" must stay distinguishable."""
        merged = merge_facts(
            [_result("probe", Fact("7", "uptime_seconds", 0, "probe"))]
        )
        assert merged["7"]["uptime_seconds"].value == 0


class TestProvenance:
    """Cover that every merged field says where it came from and when."""

    def test_observed_at_is_carried_through(self):
        """A metric fact's sample time survives the merge; staleness depends on it."""
        merged = merge_facts(
            [_result("metrics", Fact("7", "version", "7.0", "metrics", OBSERVED))]
        )
        assert merged["7"]["version"].observed_at == OBSERVED

    def test_inventory_facts_are_not_time_bounded(self):
        """Inventory is current by definition, so it carries no observation time."""
        result = inventory_facts([_service()])
        assert all(fact.observed_at is None for fact in result.facts)

    def test_helpers_split_values_from_sources(self):
        """`flatten` and `provenance` are the document's two halves."""
        merged = merge_facts(
            [
                _result("metrics", Fact("7", "version", "7.0.39-21", "metrics")),
                _result("inventory", Fact("7", "endpoint", "m1:27017", "inventory")),
            ]
        )["7"]
        assert flatten(merged) == {"version": "7.0.39-21", "endpoint": "m1:27017"}
        assert provenance(merged) == {"version": "metrics", "endpoint": "inventory"}


class TestInventoryFacts:
    """Cover the inventory source."""

    def test_endpoint_is_built_from_address_and_port(self):
        """The document's `endpoint` exists nowhere else."""
        merged = merge_facts([inventory_facts([_service()])])
        assert merged["7"]["endpoint"].value == "replicaset-cluster-node00:27017"

    def test_service_without_node_still_yields_facts(self):
        """A service with no address contributes what it has, minus the endpoint."""
        result = inventory_facts([_service(node_name=None, node_address=None)])
        fields = {fact.field for fact in result.facts}
        assert "endpoint" not in fields
        assert "service_name" in fields

    def test_external_id_coverage_is_reported(self):
        """A service with no PMM id is invisible to metrics, so the run records it."""
        services = [_service(), _service(service_id=8, external_id=None)]
        result = inventory_facts(services)
        assert result.detail["services"] == len(services)
        assert result.detail["services_with_external_id"] == 1


class TestProbeFacts:
    """Cover the probe source."""

    RECORD = {
        "binary_version": "7.0.39-21",
        "process": {"running": True, "program": "mongod", "uptime_sec": 1090},
        "system": {"os_name": "Ubuntu 24.04.3 LTS", "kernel": "6.17.0-35-generic"},
        "database": {"db_version": "7.0.39-21", "state": 1, "set_name": "rs0"},
    }

    def test_member_state_is_named_not_numeric(self):
        """`myState` 1 is PRIMARY; the document carries names, not integers."""
        merged = merge_facts([probe_facts({"7": self.RECORD})])
        assert merged["7"]["state"].value == "PRIMARY"

    def test_installed_and_running_versions_are_separate_fields(self):
        """Their divergence is the upgraded-but-not-restarted case."""
        record = self.RECORD | {"binary_version": "7.0.40-22"}
        merged = merge_facts([probe_facts({"7": record})])
        assert merged["7"]["installed_version"].value == "7.0.40-22"
        assert merged["7"]["version"].value == "7.0.39-21"

    def test_missing_record_is_partial_not_failed(self):
        """One unreachable node does not make the source useless."""
        result = probe_facts({"7": self.RECORD, "8": None})
        assert result.status is SourceStatus.PARTIAL
        assert result.detail["services_answered"] == 1

    def test_no_records_at_all_is_failed(self):
        """Every attempted service failing is a different thing from none attempted."""
        assert probe_facts({"7": None}).status is SourceStatus.FAILED

    def test_nothing_attempted_is_disabled(self):
        """A run with the probe switched off reports it as such, not as a failure."""
        assert probe_facts({}).status is SourceStatus.DISABLED

    def test_unresolved_services_are_counted(self):
        """Orphans never reach the probe, so they are reported apart from failures."""
        result = probe_facts({"7": self.RECORD}, unresolved=UNRESOLVED_SOME)
        assert result.detail["services_unresolved"] == UNRESOLVED_SOME


class TestPrecedenceTable:
    """Guard the table itself."""

    def test_every_field_names_known_sources(self):
        """A typo'd source key silently disables a field, so check them all."""
        known = {"inventory", "metrics", "probe"}
        for field, order in DEFAULT_PRECEDENCE.items():
            assert set(order) <= known, field

    def test_a_default_ordering_exists(self):
        """Fields not named in the table fall back to it."""
        assert DEFAULT_PRECEDENCE["default"]


class TestProbeStatusSemantics:
    """Pin down what the probe's status means, since the run is graded on it.

    Regression cover: the first version returned ``DISABLED`` whenever no service
    reached the probe, so a run in which POM could not execute anywhere -- the exact
    condition the probe exists to detect -- was indistinguishable from one where the
    probe had been switched off in settings.
    """

    RECORD = {"binary_version": "7.0.39-21", "process": {"running": True}}

    def test_no_executor_anywhere_is_failed_not_disabled(self):
        """POM being unable to reach a single node is a finding, not a non-event."""
        result = probe_facts({}, unresolved=UNRESOLVED_ALL)
        assert result.status is SourceStatus.FAILED
        assert result.detail["services_unresolved"] == UNRESOLVED_ALL

    def test_switched_off_is_disabled(self):
        """Nothing attempted and nothing unresolved means the source never ran."""
        assert probe_facts({}).status is SourceStatus.DISABLED

    def test_all_answered_but_some_unresolved_is_partial(self):
        """A probe that reached every node it could still missed the orphans."""
        result = probe_facts({"7": self.RECORD}, unresolved=UNRESOLVED_SOME)
        assert result.status is SourceStatus.PARTIAL

    def test_all_answered_and_none_unresolved_is_ok(self):
        """Full coverage."""
        assert probe_facts({"7": self.RECORD}).status is SourceStatus.OK


class TestReplicationPrecedence:
    """Cover the replication fields, which only VictoriaMetrics can supply."""

    @pytest.mark.parametrize(
        "field",
        ["replication_lag_seconds", "oplog_head_timestamp", "oplog_tail_timestamp"],
    )
    def test_only_metrics_may_supply_them(self, field):
        """No probe or inventory value may reach these fields.

        The probe has no concept of any of them, so a value arriving from either source
        would be fabricated -- and a fabricated zero lag is indistinguishable on screen
        from a healthy one.
        """
        merged = merge_facts(
            [
                _result("probe", Fact("7", field, 99.0, "probe")),
                _result("inventory", Fact("7", field, 99.0, "inventory")),
            ]
        )
        assert field not in merged.get("7", {})

    @pytest.mark.parametrize(
        "field",
        ["replication_lag_seconds", "oplog_head_timestamp", "oplog_tail_timestamp"],
    )
    def test_a_metrics_value_is_accepted(self, field):
        """The declared owner still wins normally."""
        merged = merge_facts([_result("metrics", Fact("7", field, 5.0, "metrics"))])
        assert merged["7"][field].value == ACCEPTED_VALUE

    def test_zero_lag_survives_the_merge(self):
        """`0` is a real reading; the presence rule must not drop it."""
        merged = merge_facts(
            [_result("metrics", Fact("7", "replication_lag_seconds", 0.0, "metrics"))]
        )
        assert merged["7"]["replication_lag_seconds"].value == 0.0
