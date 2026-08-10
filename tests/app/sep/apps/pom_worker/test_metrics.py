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

"""Test the VictoriaMetrics exposition rendering and chunking.

The chunk ceiling is the reason these tests matter. VictoriaMetrics caps a label
value at 4096 bytes and drops an oversized sample **silently**, answering ``204``
either way -- so a chunking bug does not fail loudly, it just loses data. Every
chunk is asserted against the ceiling *after* escaping, because that is what the
server measures.
"""

import json
from uuid import UUID

from app.sep.apps.pom_worker.metrics import (
    build_exposition,
    chunk_label,
    escape_label_value,
    MAX_LABEL_BYTES,
    node_labels,
    render_sample,
)
from app.sep.apps.pom_worker.models import NodeResolution, ProbeStatus

EXECUTION_ID = UUID("008a3b4c-3c09-4b2a-8da2-6806dad45360")
#: Nodes in the multi-node exposition fixture.
NODE_COUNT = 3


class TestEscapeLabelValue:
    """Cover the three escapes the exposition format defines."""

    def test_escapes_backslash_quote_and_newline(self) -> None:
        """The three defined escapes are applied."""
        assert escape_label_value('a\\b"c\nd') == 'a\\\\b\\"c\\nd'

    def test_leaves_carriage_return_literal(self) -> None:
        r"""``\r`` is not a valid escape and must pass through as a raw byte.

        Emitting ``\r`` would make the parser reject the sample outright.
        """
        assert escape_label_value("a\rb") == "a\rb"

    def test_leaves_other_characters_untouched(self) -> None:
        """Tabs and unicode are copied through unchanged."""
        assert escape_label_value("a\tbé") == "a\tbé"


class TestChunkLabel:
    """Cover splitting a blob into label-sized chunks."""

    def test_short_value_is_one_chunk(self) -> None:
        """A value below the chunk size is not split."""
        assert chunk_label("hello") == ["hello"]

    def test_empty_value_yields_one_empty_chunk(self) -> None:
        """An empty blob still produces a single chunk rather than nothing."""
        assert chunk_label("") == [""]

    def test_round_trips_exactly(self) -> None:
        """Concatenating the chunks reproduces the input."""
        blob = json.dumps({"nodes": [{"n": index} for index in range(500)]})

        assert "".join(chunk_label(blob, size=100)) == blob

    def test_every_chunk_fits_the_ceiling_after_escaping(self) -> None:
        """No chunk exceeds the server-side cap once escaped.

        The blob is all backslashes, which escaping doubles -- the worst case, and
        the one a naive length check on the raw string would get wrong.
        """
        for chunk in chunk_label("\\" * 20_000):
            assert len(escape_label_value(chunk)) <= MAX_LABEL_BYTES

    def test_size_larger_than_ceiling_is_clamped(self) -> None:
        """A caller asking for oversized chunks still gets compliant ones."""
        for chunk in chunk_label("x" * 20_000, size=999_999):
            assert len(escape_label_value(chunk)) <= MAX_LABEL_BYTES


class TestRenderSample:
    """Cover one exposition line."""

    def test_drops_empty_and_none_labels(self) -> None:
        """Absent labels are omitted rather than rendered empty."""
        line = render_sample("m", {"a": "1", "b": None, "c": ""}, 1)

        assert line == 'm{a="1"} 1'

    def test_renders_without_braces_when_no_labels_survive(self) -> None:
        """A sample with no usable labels is still valid exposition."""
        assert render_sample("m", {"a": None}, 7) == "m 7"

    def test_sorts_labels_for_stable_output(self) -> None:
        """Label order is deterministic, so runs diff cleanly."""
        assert render_sample("m", {"b": "2", "a": "1"}, 1) == 'm{a="1",b="2"} 1'


class TestBuildExposition:
    """Cover the assembled body for one run."""

    def test_emits_run_ts_and_one_series_per_node(self) -> None:
        """The run timestamp is the value; each node gets its own series."""
        rows = [
            node_labels(
                service_name=f"svc-{index}",
                cluster="c",
                replication_set="rs",
                executor_host="host",
                resolution=NodeResolution.NAME,
                probe_status=ProbeStatus.OK,
                probe={"binary_version": "7.0.39-21"},
            )
            for index in range(NODE_COUNT)
        ]

        body = build_exposition(EXECUTION_ID, 1786050526, rows)

        assert f'pom_run_ts{{execution_id="{EXECUTION_ID}"}} 1786050526' in body
        assert body.count("pom_node{") == NODE_COUNT
        assert 'mongod_version="7.0.39-21"' in body
        assert "pom_result" not in body

    def test_omits_raw_series_when_not_requested(self) -> None:
        """The raw-JSON series is opt-in."""
        assert "pom_result" not in build_exposition(EXECUTION_ID, 1, [])

    def test_raw_series_chunks_are_numbered_and_reassemble(self) -> None:
        """Chunks carry their index and total, and rejoin to the original JSON."""
        raw = {
            "hosts": {f"h{index}": {"services": [f"s{index}"]} for index in range(400)}
        }

        body = build_exposition(EXECUTION_ID, 1, [], raw)

        chunks = {}
        for line in body.splitlines():
            if not line.startswith("pom_result{"):
                continue
            labels = line[len("pom_result{") : line.rindex("}")]
            index = labels.split('chunk="')[1].split('"')[0]
            value = labels.split('result_json="')[1].rsplit('"', 1)[0]
            chunks[index] = value
        rejoined = "".join(chunks[key] for key in sorted(chunks))

        assert len(chunks) > 1, "the fixture must be large enough to split"
        assert json.loads(rejoined.replace('\\"', '"').replace("\\\\", "\\")) == raw
        assert all(
            f'chunks="{len(chunks):04d}"' in line
            for line in body.splitlines()
            if line.startswith("pom_result{")
        )


class TestNodeLabels:
    """Cover the per-service label set."""

    def test_orphaned_node_carries_no_executor_host(self) -> None:
        """An orphaned service is labelled as such and names no host."""
        labels = node_labels(
            service_name="rsc-node02",
            cluster="rs-cluster",
            replication_set="rsc",
            executor_host=None,
            resolution=NodeResolution.ORPHANED,
            probe_status=ProbeStatus.SKIPPED,
            probe=None,
        )

        assert labels["executor_host"] is None
        assert labels["resolution"] == "orphaned"
        assert labels["probe_status"] == "skipped"
        assert labels["mongod_version"] is None

    def test_binary_version_preferred_over_database_version(self) -> None:
        """The installed binary is the upgrade-relevant version, so it wins.

        The running server can lag the installed binary after a package upgrade
        without a restart, which is exactly the case an upgrade check must catch.
        """
        labels = node_labels(
            service_name="svc",
            cluster=None,
            replication_set=None,
            executor_host="host",
            resolution=NodeResolution.NAME,
            probe_status=ProbeStatus.OK,
            probe={"binary_version": "7.0.40", "database": {"db_version": "7.0.39"}},
        )

        assert labels["mongod_version"] == "7.0.40"
        assert labels["db_version"] == "7.0.39"
