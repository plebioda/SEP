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

"""Test the VictoriaMetrics source against recorded query responses.

The payloads below are real: label sets copied from this workspace's VictoriaMetrics
on 2026-08-07, trimmed to the labels the catalog reads. No live VM is contacted.
"""

from datetime import datetime, timedelta, UTC

import pytest

from app.sep.apps.pom_worker.facts import ServiceKey, SourceStatus
from app.sep.apps.pom_worker.metrics_catalog import (
    by_metric,
    MEMBERS_SELF,
    Signal,
    SIGNALS,
    signals_for,
    Value,
    VERSION_INFO,
)
from app.sep.apps.pom_worker.metrics_source import (
    build_query,
    collect_metric_facts,
    parse_series,
)

#: 2026-08-07T12:00:00Z, the reference time every staleness assertion measures from.
NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
#: Sample values are `lag()` output: **age in seconds**, not a timestamp.
FRESH_AGE = 30.0
STALE_AGE = 90_000.0

#: The catalog reads two metrics, so a full collection costs two queries.
CATALOG_QUERIES = 2

#: The default staleness threshold every collection in this module runs with.
MAX_AGE = 300

NODE00 = "ff0275b6-3633-474a-8068-3c39d3c7a4da"
NODE02 = "6457fc75-9d38-4cd3-8aab-7b2534c6d0b0"

SERVICES = [
    ServiceKey(key="7", name="replicaset-cluster-node00", external_id=NODE00),
    ServiceKey(key="9", name="replicaset-cluster-node02", external_id=NODE02),
]


def _version_series(service_id: str, node_name: str, age: float) -> dict:
    """Build one `mongodb_version_info` series as VictoriaMetrics returns it."""
    return {
        "metric": {
            "service_id": service_id,
            "service_name": node_name,
            "service_type": "mongodb",
            "node_name": node_name,
            "cluster": "replicaset-cluster",
            "replication_set": "replicaset-cluster",
            "environment": "sandbox",
            "mongodb": "7.0.39-21",
            "vendor": "Percona",
            "edition": "Community",
        },
        "value": [1786137000, str(age)],
    }


def _members_self_series(service_id: str, state: str, age: float) -> dict:
    """Build one `mongodb_members_self` series."""
    return {
        "metric": {
            "service_id": service_id,
            "member_state": state,
            "member_idx": "replicaset-cluster-node00:27017",
            "rs_nm": "replicaset-cluster",
        },
        "value": [1786137000, str(age)],
    }


def _payload(*series: dict) -> dict:
    """Wrap series in the `/api/v1/query` envelope."""
    return {
        "status": "success",
        "data": {"resultType": "vector", "result": list(series)},
    }


class FakePMM:
    """Answer queries from a canned metric-to-payload mapping."""

    def __init__(self, payloads: dict[str, dict], fail: set[str] | None = None):
        self.payloads = payloads
        self.fail = fail or set()
        self.queries: list[str] = []

    async def get(self, path: str, params: dict) -> dict:
        """Return the payload for whichever catalog metric the query names."""
        query = params["query"]
        self.queries.append(query)
        for metric in (VERSION_INFO, MEMBERS_SELF):
            if metric in query:
                if metric in self.fail:
                    raise RuntimeError(f"{metric} exploded")
                return self.payloads.get(metric, _payload())
        return _payload()


class FakePMMByTemplate:
    """Answer the age query and the value query with different payloads."""

    def __init__(self, age_payload: dict, value_payload: dict):
        self.age_payload = age_payload
        self.value_payload = value_payload
        self.queries: list[str] = []

    async def get(self, path: str, params: dict) -> dict:
        """Return whichever payload matches the query's rollup function."""
        query = params["query"]
        self.queries.append(query)
        return self.age_payload if query.startswith("lag(") else self.value_payload


async def _collect(pmm, services=None, **overrides):
    """Run the collector with sandbox-shaped defaults."""
    kwargs = {
        "lookback": "24h",
        "max_age_seconds": MAX_AGE,
        "batch_size": 50,
        "now": NOW,
    }
    kwargs.update(overrides)
    return await collect_metric_facts(
        pmm, services if services is not None else SERVICES, SIGNALS, **kwargs
    )


class TestBuildQuery:
    """Cover the query the collector issues."""

    def test_pins_to_service_ids_and_wraps_for_staleness(self):
        """`timestamp(last_over_time(...))` yields labels and sample age in one query."""
        query = build_query(VERSION_INFO, [NODE02, NODE00], "24h")
        # Sorted, so NODE02 (leading digit) precedes NODE00 (leading letter).
        assert query == (f'lag({VERSION_INFO}{{service_id=~"{NODE02}|{NODE00}"}}[24h])')

    def test_ids_are_sorted_so_the_query_is_stable(self):
        """A stable query string is cacheable and diffable between runs."""
        assert build_query(VERSION_INFO, [NODE00, NODE02], "24h") == build_query(
            VERSION_INFO, [NODE02, NODE00], "24h"
        )

    @pytest.mark.parametrize(
        "metric", ["mongodb_ss_.*", 'x"} or up{', "rate(a[5m])", ""]
    )
    def test_refuses_anything_that_is_not_a_bare_metric_name(self, metric):
        """The matcher is appended textually, so the metric may not be an expression."""
        with pytest.raises(ValueError, match="bare metric name"):
            build_query(metric, [NODE00], "24h")

    def test_refuses_an_id_that_could_escape_the_matcher(self):
        """Ids reach a PromQL regex; anything unexpected is refused, not escaped."""
        with pytest.raises(ValueError, match="usable service id"):
            build_query(VERSION_INFO, ['abc"} or up{'], "24h")


class TestParseSeries:
    """Cover response parsing, which must degrade rather than raise."""

    def test_reads_labels_and_value(self):
        """The happy path."""
        parsed = parse_series(_payload(_version_series(NODE00, "node00", FRESH_AGE)))
        assert parsed[0][0]["vendor"] == "Percona"
        assert parsed[0][1] == pytest.approx(FRESH_AGE)

    @pytest.mark.parametrize(
        "payload",
        [None, {}, {"data": None}, {"data": {"result": "nope"}}, "text", []],
    )
    def test_malformed_payloads_yield_nothing(self, payload):
        """A metrics source that cannot answer degrades the run; it does not fail it."""
        assert parse_series(payload) == []

    def test_unreadable_series_are_skipped_individually(self):
        """One bad series must not lose the good ones beside it."""
        good = _version_series(NODE00, "node00", FRESH_AGE)
        # Neither malformed entry carries a usable sample pair, so only `good` survives.
        parsed = parse_series(_payload({"metric": {}}, {"nope": 1}, good))
        assert len(parsed) == 1
        assert parsed[0][0]["service_id"] == NODE00


class TestCollectMetricFacts:
    """Cover the collector end to end, over recorded payloads."""

    @pytest.fixture
    def pmm(self):
        """Return a PMM client answering both catalog queries for both services."""
        return FakePMM(
            {
                VERSION_INFO: _payload(
                    _version_series(NODE00, "replicaset-cluster-node00", FRESH_AGE),
                    _version_series(NODE02, "replicaset-cluster-node02", FRESH_AGE),
                ),
                MEMBERS_SELF: _payload(
                    _members_self_series(NODE00, "PRIMARY", FRESH_AGE),
                    _members_self_series(NODE02, "SECONDARY", FRESH_AGE),
                ),
            }
        )

    async def test_one_query_per_metric_not_per_signal(self, pmm):
        """Nine signals over two metrics cost two round trips, and must keep doing so."""
        await _collect(pmm)
        assert len(pmm.queries) == len(by_metric(SIGNALS)) == CATALOG_QUERIES

    async def test_collects_the_fields_the_document_needs(self, pmm):
        """Vendor and edition are the ones nothing else can supply."""
        result = await _collect(pmm)
        node00 = {f.field: f.value for f in result.facts if f.service == "7"}
        assert node00["version"] == "7.0.39-21"
        assert node00["vendor"] == "Percona"
        assert node00["edition"] == "Community"
        assert node00["state"] == "PRIMARY"
        assert node00["host"] == "replicaset-cluster-node00"

    async def test_full_coverage_is_ok(self, pmm):
        """Every service answered."""
        result = await _collect(pmm)
        assert result.status is SourceStatus.OK
        assert result.detail["services_covered"] == len(SERVICES)

    async def test_partial_coverage_is_partial(self):
        """A service the exporter never reported is missing, not wrong."""
        pmm = FakePMM(
            {
                VERSION_INFO: _payload(
                    _version_series(NODE00, "replicaset-cluster-node00", FRESH_AGE)
                )
            }
        )
        result = await _collect(pmm)
        assert result.status is SourceStatus.PARTIAL
        assert result.detail["services_covered"] == 1

    async def test_no_coverage_is_failed(self):
        """Nothing answered at all."""
        result = await _collect(FakePMM({}))
        assert result.status is SourceStatus.FAILED
        assert result.facts == ()

    async def test_a_failing_query_does_not_lose_the_other(self, pmm):
        """One metric exploding must not cost the fields the other one carries."""
        pmm.fail = {MEMBERS_SELF}
        result = await _collect(pmm)
        fields = {fact.field for fact in result.facts}
        assert "version" in fields
        assert "state" not in fields
        assert result.status is SourceStatus.PARTIAL
        assert result.detail["errors"]

    async def test_stale_samples_are_kept_and_counted(self):
        """Discarding them would erase "gone" versus "not scraped since Tuesday"."""
        pmm = FakePMM(
            {
                VERSION_INFO: _payload(
                    _version_series(NODE00, "replicaset-cluster-node00", STALE_AGE)
                )
            }
        )
        result = await _collect(pmm)
        assert result.detail["stale_services"] == 1
        assert result.detail["oldest_sample_age_seconds"] == round(STALE_AGE)
        assert any(fact.field == "version" for fact in result.facts)

    async def test_facts_carry_the_sample_time(self, pmm):
        """Every metric fact is time-bounded; that is what makes staleness derivable."""
        result = await _collect(pmm)
        assert all(fact.observed_at is not None for fact in result.facts)

    async def test_a_stale_generation_is_never_attributed_to_a_live_row(self, pmm):
        """The guard behind the pinned matcher: an unknown service_id is dropped."""
        pmm.payloads[VERSION_INFO] = _payload(
            _version_series(
                "dead-generation-uuid", "replicaset-cluster-node00", FRESH_AGE
            )
        )
        result = await _collect(pmm)
        assert all(fact.field == "state" for fact in result.facts)

    async def test_services_without_a_pmm_id_are_counted_not_guessed(self, pmm):
        """No external id means nothing to pin a query to -- and no name-based guess."""
        services = [*SERVICES, ServiceKey(key="11", name="orphan", external_id=None)]
        result = await _collect(pmm, services)
        assert result.detail["services_without_external_id"] == 1
        assert result.status is SourceStatus.PARTIAL

    async def test_no_services_carry_ids_at_all(self):
        """A run that cannot query anything says so rather than reporting success."""
        services = [ServiceKey(key="11", name="orphan", external_id=None)]
        result = await _collect(FakePMM({}), services)
        assert result.status is SourceStatus.FAILED
        assert result.detail["errors"]

    async def test_disabling_a_group_drops_its_query(self, pmm):
        """`METRICS_GROUPS` is a cost dial, not only a content one."""
        await collect_metric_facts(
            pmm,
            SERVICES,
            signals_for(["identity"]),
            lookback="24h",
            max_age_seconds=MAX_AGE,
            batch_size=50,
            now=NOW,
        )
        assert len(pmm.queries) == 1
        assert MEMBERS_SELF not in pmm.queries[0]

    async def test_services_are_batched_across_queries(self, pmm):
        """The pinning matcher grows with the estate, so it is chunked."""
        await _collect(pmm, batch_size=1)
        assert len(pmm.queries) == CATALOG_QUERIES * len(SERVICES)


class TestSampleAgeSemantics:
    """Pin down that the sample value is an age, not a timestamp.

    Regression cover for a real bug: the collector first queried
    ``timestamp(last_over_time(m[24h]))``, which *looks* like it yields the sample's own
    timestamp and actually yields the evaluation time rounded to the step. Every service
    then reported a sample a few seconds old, including services whose exporter had been
    down for half a day -- the failure mode that makes a dead estate look healthy.
    """

    async def test_observed_at_is_derived_from_the_age(self):
        """An eleven-hour-old sample must date from eleven hours ago, not from now."""
        pmm = FakePMM(
            {
                VERSION_INFO: _payload(
                    _version_series(NODE00, "replicaset-cluster-node00", STALE_AGE)
                )
            }
        )
        result = await _collect(pmm)
        observed = {fact.observed_at for fact in result.facts}
        assert observed == {NOW - timedelta(seconds=STALE_AGE)}

    async def test_a_stale_sample_is_never_reported_as_fresh(self):
        """The specific assertion the old query silently violated."""
        pmm = FakePMM(
            {
                VERSION_INFO: _payload(
                    _version_series(NODE00, "replicaset-cluster-node00", STALE_AGE)
                )
            }
        )
        result = await _collect(pmm)
        assert result.detail["oldest_sample_age_seconds"] > MAX_AGE
        assert result.detail["stale_services"] == 1

    async def test_the_age_query_is_lag_not_timestamp(self):
        """`timestamp(last_over_time(...))` must not come back."""
        pmm = FakePMM({})
        await _collect(pmm)
        assert all(query.startswith("lag(") for query in pmm.queries)
        assert not any("timestamp(" in query for query in pmm.queries)


class TestValueSignals:
    """Cover the second query, which exists for the health job."""

    async def test_label_only_signals_issue_one_query_per_metric(self):
        """`lag` alone suffices when nothing reads the sample value."""
        pmm = FakePMM({})
        await collect_metric_facts(
            pmm,
            SERVICES,
            signals_for(["identity"]),
            lookback="24h",
            max_age_seconds=MAX_AGE,
            batch_size=50,
            now=NOW,
        )
        assert len(pmm.queries) == 1

    async def test_a_value_signal_adds_the_value_query(self):
        """`lag`'s value is the age, so a Value signal needs its own query."""
        pmm = FakePMM({})
        signal = Signal("uptime_seconds", VERSION_INFO, Value(int), "identity")
        await collect_metric_facts(
            pmm,
            SERVICES,
            [signal],
            lookback="24h",
            max_age_seconds=MAX_AGE,
            batch_size=50,
            now=NOW,
        )
        assert len(pmm.queries) == CATALOG_QUERIES
        assert any(q.startswith("lag(") for q in pmm.queries)
        assert any(q.startswith("last_over_time(") for q in pmm.queries)

    async def test_a_value_signal_reads_the_value_not_the_age(self):
        """The whole point: 1203 seconds of uptime, not 30 seconds of staleness."""
        age = _payload(_version_series(NODE00, "replicaset-cluster-node00", FRESH_AGE))
        value = _payload(_version_series(NODE00, "replicaset-cluster-node00", 1203.0))
        pmm = FakePMMByTemplate(age, value)
        signal = Signal("uptime_seconds", VERSION_INFO, Value(int), "identity")
        result = await collect_metric_facts(
            pmm,
            SERVICES,
            [signal],
            lookback="24h",
            max_age_seconds=MAX_AGE,
            batch_size=50,
            now=NOW,
        )
        assert [fact.value for fact in result.facts] == [1203]
