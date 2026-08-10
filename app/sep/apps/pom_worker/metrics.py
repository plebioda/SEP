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

"""Emit one discovery run's result to VictoriaMetrics, for querying in vmui.

Writes directly to VM's Prometheus import endpoint through pmm-server's
authenticated surface, using the PMM credentials SEP already holds -- so this is a
``post()`` on the existing :class:`~app.sep.clients.pmm.PMMRemoteAPI`, not a new
client. This is the *other* metrics write path from the ``.prom`` textfile route the
backup payloads use; the textfile route needs the file to land on a monitored host,
which a value SEP computes centrally has no natural home on.

Three things to know about the target, all measured rather than assumed:

* **A metric value is a float64.** The result JSON cannot be a value; it can only be
  a label.
* **A label value is capped at 4096 bytes, and exceeding it is silent** -- the push
  returns ``204`` and the sample is discarded. Hence :func:`chunk_label` and hence
  Postgres, not VM, holding the full result.
* **A pushed sample is invisible for ~30s** (VictoriaMetrics' ``-search.latencyOffset``),
  and instant queries look back only 5 minutes. A read-back immediately after a run
  returns nothing; that is not a failure.

Emission never fails the job -- the same rule the ``.prom`` writers follow. A run
whose metrics did not land is still a run whose mapping and probe results are in
Postgres.
"""

import json
import logging
from typing import Any
from uuid import UUID

from app.sep.apps.pom_worker.config import pom_worker_settings
from app.sep.apps.pom_worker.models import NodeResolution, ProbeStatus
from app.sep.clients.pmm import PMMRemoteAPI

logger = logging.getLogger(__name__)

#: VictoriaMetrics' Prometheus text-exposition import endpoint, behind pmm-server's
#: authenticated surface. The ``/prometheus`` prefix is VM's ``-http.pathPrefix``;
#: without it the endpoint answers 400.
IMPORT_PATH = "/prometheus/api/v1/import/prometheus"
#: Hard ceiling on one label value, measured against this PMM's VictoriaMetrics:
#: 4096 bytes is stored, 4097 is silently dropped.
MAX_LABEL_BYTES = 4096
#: Leave room for the JSON escaping to grow a chunk past the ceiling. Escaping can
#: double a pathological chunk, but the result JSON is mostly plain text; a quarter
#: is comfortable and keeps chunk counts sane.
CHUNK_BYTES = 3000


def escape_label_value(value: str) -> str:
    r"""Escape a label value per the exposition format's three escapes.

    The format defines exactly ``\\\\``, ``\\"`` and ``\\n`` inside a label value and
    its parser *rejects* any other escape sequence -- notably ``\\r``, which must be
    passed through literally rather than escaped.

    :param value: The raw label value.
    :return: The value safe to place inside double quotes.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_labels(labels: dict[str, Any]) -> str:
    """Render a label mapping as exposition-format label pairs.

    Labels whose value is ``None`` or empty are dropped rather than emitted empty:
    an absent label is queryable in vmui as ``{label=""}`` either way, and dropping
    keeps the series readable.

    :param labels: The label names and values.
    :return: The rendered ``name="value",…`` body, without braces.
    """
    return ",".join(
        f'{name}="{escape_label_value(str(value))}"'
        for name, value in sorted(labels.items())
        if value is not None and value != ""
    )


def render_sample(metric: str, labels: dict[str, Any], value: float) -> str:
    """Render one exposition-format sample line.

    :param metric: The metric name.
    :param labels: The label mapping.
    :param value: The sample value.
    :return: One exposition line.
    """
    body = render_labels(labels)
    return f"{metric}{{{body}}} {value}" if body else f"{metric} {value}"


def chunk_label(value: str, size: int = CHUNK_BYTES) -> list[str]:
    """Split a string into chunks that survive the label-value ceiling.

    Splits on the *escaped* length, because that is what VictoriaMetrics measures.

    :param value: The string to split.
    :param size: The maximum raw chunk length.
    :return: The chunks, in order.
    """
    chunks: list[str] = []
    current = ""
    for char in value:
        candidate = current + char
        if len(escape_label_value(candidate)) > min(size, MAX_LABEL_BYTES):
            chunks.append(current)
            current = char
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks or [""]


def build_exposition(
    execution_id: UUID,
    started_ts: int,
    rows: list[dict[str, Any]],
    raw_result: dict[str, Any] | None = None,
) -> str:
    """Build the full exposition body for one run.

    Three series:

    * ``pom_run_ts`` -- when the run happened, the timestamp *as the value*,
      which is what a float64 value is actually good for.
    * ``pom_node`` -- one series per service, carrying the facts worth
      filtering on. This is the series that makes vmui worth opening.
    * ``pom_result`` -- the raw JSON, chunked, emitted only when
      ``emit_raw_json`` is on.

    :param execution_id: The run's id, carried as a label on every series.
    :param started_ts: The run's start, as unix seconds.
    :param rows: One mapping per service, as :func:`node_labels` expects.
    :param raw_result: The full result to chunk into ``pom_result``, or ``None``.
    :return: The exposition text to POST.
    """
    execution = str(execution_id)
    lines = [
        "# HELP pom_run_ts Unix timestamp of a POM worker run.",
        "# TYPE pom_run_ts untyped",
        render_sample("pom_run_ts", {"execution_id": execution}, started_ts),
        "# HELP pom_node One POM worker probed or orphaned service.",
        "# TYPE pom_node untyped",
    ]
    lines.extend(
        render_sample("pom_node", {**labels, "execution_id": execution}, 1)
        for labels in rows
    )

    if raw_result is not None:
        blob = json.dumps(raw_result, separators=(",", ":"), default=str)
        chunks = chunk_label(blob)
        lines.append("# HELP pom_result Raw POM worker result JSON, chunked.")
        lines.append("# TYPE pom_result untyped")
        lines.extend(
            render_sample(
                "pom_result",
                {
                    "execution_id": execution,
                    "chunk": f"{index:04d}",
                    "chunks": f"{len(chunks):04d}",
                    "result_json": chunk,
                },
                1,
            )
            for index, chunk in enumerate(chunks)
        )
    return "\n".join(lines) + "\n"


def node_labels(
    service_name: str,
    cluster: str | None,
    replication_set: str | None,
    executor_host: str | None,
    resolution: NodeResolution,
    probe_status: ProbeStatus,
    probe: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the label set for one service's ``pom_node`` series.

    :param service_name: The inventory service name.
    :param cluster: The service's cluster.
    :param replication_set: The service's replica set.
    :param executor_host: The resolved executor host, if any.
    :param resolution: How the executor host was matched.
    :param probe_status: The probe outcome.
    :param probe: The probe record, when one came back.
    :return: The label mapping.
    """
    database = (probe or {}).get("database") or {}
    system = (probe or {}).get("system") or {}
    process = (probe or {}).get("process") or {}
    return {
        "service": service_name,
        "cluster": cluster,
        "replication_set": replication_set,
        "executor_host": executor_host,
        "resolution": resolution.value,
        "probe_status": probe_status.value,
        "mongod_version": (probe or {}).get("binary_version")
        or database.get("db_version"),
        "db_version": database.get("db_version"),
        "os": system.get("os_name"),
        "kernel": system.get("kernel"),
        "server_running": str(process.get("running")).lower() if process else None,
        "server_process": process.get("program") if process else None,
        "set_name": database.get("set_name"),
        "state": database.get("state"),
    }


async def emit(pmm_api: PMMRemoteAPI, exposition: str) -> bool:
    """Push an exposition body to VictoriaMetrics, best-effort.

    :param pmm_api: The PMM API client, which already carries the credentials.
    :param exposition: The exposition text to import.
    :return: Whether the push was accepted. Note that acceptance is not storage --
        an oversized label is dropped behind a ``204``.
    """
    if not pom_worker_settings.EMIT_METRICS:
        logger.debug("POM worker: metric emission disabled; skipping")
        return False
    try:
        await pmm_api.post(IMPORT_PATH, data=exposition.encode("utf-8"))
    except Exception:
        logger.exception("POM worker: failed to emit metrics to VictoriaMetrics")
        return False
    logger.info(
        "POM worker: emitted %d exposition line(s) to VictoriaMetrics; allow ~30s "
        "before querying in vmui (search.latencyOffset)",
        exposition.count("\n"),
    )
    return True
