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

"""Read the status document's facts out of VictoriaMetrics.

The read counterpart of :mod:`~app.sep.apps.pom_worker.metrics`, which writes. Both
ride the same authenticated pmm-server surface on the existing
:class:`~app.sep.clients.pmm.PMMRemoteAPI`, so this is a ``get()`` on a client SEP
already holds rather than a new one. VictoriaMetrics' own ``:9090`` is published but
**not reachable from where SEP runs**; do not design against it.

Which fields come from where is declared in
:mod:`~app.sep.apps.pom_worker.metrics_catalog`, not here. This module only knows how
to turn that catalog into queries and the answers back into
:class:`~app.sep.apps.pom_worker.facts.Fact` records.

Three measured properties of the target shape every query issued here:

* **Instant queries look back only five minutes**, and a freshly written sample is
  invisible for ~30s. A bare ``mongodb_version_info`` returns nothing whenever
  scraping paused, which is indistinguishable from "no such service" unless the query
  is given an explicit window.
* **The sample's own age is the thing that matters, and it is surprisingly hard to
  get.** ``last_over_time`` does not carry it -- the returned sample is stamped at the
  *evaluation* time -- and neither does ``timestamp(last_over_time(...))``, which looks
  like it should and instead reports the evaluation time rounded down to the step. That
  reads as "fresh" for a series last scraped days ago, which is the single most
  dangerous way to be wrong here. :data:`AGE_TEMPLATE` therefore uses MetricsQL's
  **`lag()`**, whose value *is* the seconds since the last raw sample and which
  preserves every label. Measured against this workspace's VM: ``lag`` returned 40834
  for a node whose containers had been down about eleven hours, while
  ``timestamp(last_over_time(...))`` claimed a 34-second-old sample.
* **``service_name`` is not a key.** Re-registration mints fresh PMM UUIDs while
  reusing the name, and superseded series survive until retention expires -- 38 names
  resolve to 206 ``service_id`` values here. Every query is therefore pinned to the
  exact ``external_id`` set inventory currently knows about, which excludes dead
  generations by construction rather than by picking a winner afterwards.

``lag()`` is MetricsQL, not PromQL. That is deliberate and safe -- the target is
VictoriaMetrics, reached through pmm-server -- but it is the one thing here that would
not run against a stock Prometheus.
"""

import logging
import re
from collections.abc import Sequence
from datetime import datetime, timedelta, UTC
from typing import Any

from app.sep.apps.pom_worker.facts import (
    Fact,
    ServiceKey,
    SourceResult,
    SourceStatus,
)
from app.sep.apps.pom_worker.metrics_catalog import (
    by_metric,
    Signal,
    Value,
)
from app.sep.clients.pmm import PMMRemoteAPI

logger = logging.getLogger(__name__)

__all__ = [
    "AGE_TEMPLATE",
    "SOURCE_KEY",
    "VALUE_TEMPLATE",
    "build_expression_query",
    "build_query",
    "collect_metric_facts",
    "parse_series",
]

#: The source key every fact from here carries.
SOURCE_KEY = "metrics"

#: VictoriaMetrics' instant-query endpoint, behind pmm-server's authenticated surface.
#: The ``/prometheus`` prefix is VM's ``-http.pathPrefix``; without it the endpoint 400s.
QUERY_PATH = "/prometheus/api/v1/query"

#: The primary query: MetricsQL ``lag()``, whose **value is the age in seconds** of the
#: series' last raw sample, with every label preserved. One query therefore yields both
#: the labels the catalog reads and the staleness the run records. ``lag`` drops
#: ``__name__``, so the caller must remember which metric it asked for rather than
#: reading it back off the series. See the module docstring for why the obvious
#: ``timestamp(last_over_time(...))`` is wrong.
AGE_TEMPLATE = "lag({metric}{{{matcher}}}[{lookback}])"

#: The secondary query, issued **only** for metrics carrying at least one
#: :class:`~app.sep.apps.pom_worker.metrics_catalog.Value` signal, because ``lag``'s
#: value is the age rather than the metric's own. The discovery catalog is entirely
#: label reads, so today this is never issued; the health job will need it.
VALUE_TEMPLATE = "last_over_time({metric}{{{matcher}}}[{lookback}])"

#: A bare metric name. Catalog metrics are interpolated into PromQL, so they are checked
#: rather than trusted, even though the catalog is source code today.
_METRIC_NAME = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")

#: PMM service UUIDs. Anything else is refused rather than escaped, because a value that
#: is not a UUID has no business reaching a PromQL regex matcher.
_EXTERNAL_ID = re.compile(r"^[A-Za-z0-9-]+$")

#: A Prometheus instant-query sample is the pair ``[timestamp, value]``.
_SAMPLE_PAIR_LENGTH = 2


def _matcher(external_ids: Sequence[str]) -> str:
    """Return the ``service_id`` selector pinning a query to the live service set.

    :param external_ids: The PMM service UUIDs to pin to.
    :return: The matcher, without surrounding braces.
    :raises ValueError: When an id is not of the expected shape.
    """
    for external_id in external_ids:
        if not _EXTERNAL_ID.match(external_id):
            raise ValueError(f"not a usable service id: {external_id!r}")
    return f'service_id=~"{"|".join(sorted(external_ids))}"'


def build_query(
    metric: str,
    external_ids: Sequence[str],
    lookback: str,
    template: str = AGE_TEMPLATE,
) -> str:
    """Return the query for one metric, pinned to a set of live services.

    :param metric: The bare metric name from the catalog.
    :param external_ids: The PMM service UUIDs to pin to.
    :param lookback: The rollup window, e.g. ``24h``.
    :param template: :data:`AGE_TEMPLATE` or :data:`VALUE_TEMPLATE`.
    :return: The query string.
    :raises ValueError: When the metric name or any id is not of the expected shape.
    """
    if not _METRIC_NAME.match(metric):
        raise ValueError(f"not a bare metric name: {metric!r}")
    return template.format(
        metric=metric, matcher=_matcher(external_ids), lookback=lookback
    )


def build_expression_query(query: str, external_ids: Sequence[str]) -> str:
    """Return a :attr:`Signal.query` expression with its matcher injected.

    :param query: The catalog's PromQL template, carrying ``{matcher}`` placeholders.
    :param external_ids: The PMM service UUIDs to pin to.
    :return: The query string.
    :raises ValueError: When an id is not of the expected shape, or the template names
        no matcher -- an unpinned expression would silently span dead generations.
    """
    if "{matcher}" not in query:
        raise ValueError(f"expression names no {{matcher}}: {query!r}")
    return query.format(matcher=_matcher(external_ids))


def _join_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Return a label set's identity, for joining the age and value queries.

    Keyed on the whole label set rather than ``service_id`` because a metric may carry
    several series per service -- ``mongodb_rs_members_state`` has one per peer -- and
    collapsing those onto the service would pair a value with the wrong member.
    ``__name__`` is excluded because ``lag`` drops it and ``last_over_time`` keeps it.

    :param labels: The series' labels.
    :return: The join key.
    """
    return tuple(sorted((k, v) for k, v in labels.items() if k != "__name__"))


def parse_series(
    payload: Any,
) -> list[tuple[dict[str, str], float]]:
    """Return ``(labels, value)`` for each series in a VictoriaMetrics query response.

    Tolerant on purpose: a malformed or partial response yields the series it can read
    rather than raising, because a metrics source that cannot answer must degrade the
    run rather than fail it.

    :param payload: The decoded ``/api/v1/query`` response body.
    :return: One entry per readable series.
    """
    if not isinstance(payload, dict):
        return []
    result = (payload.get("data") or {}).get("result")
    if not isinstance(result, list):
        return []

    series: list[tuple[dict[str, str], float]] = []
    for entry in result:
        if not isinstance(entry, dict):
            continue
        labels = entry.get("metric")
        value = entry.get("value")
        if not isinstance(labels, dict) or not isinstance(value, list | tuple):
            continue
        if len(value) < _SAMPLE_PAIR_LENGTH:
            continue
        try:
            series.append(
                ({str(k): str(v) for k, v in labels.items()}, float(value[1]))
            )
        except (TypeError, ValueError):
            continue
    return series


def _chunks(items: Sequence[str], size: int) -> list[Sequence[str]]:
    """Split ``items`` into chunks of at most ``size``.

    Queries are chunked because the pinning matcher is a ``|``-joined list of UUIDs:
    one per service, 37 bytes each. That is comfortable for a sandbox and a 36 KB query
    string for a thousand-service estate.

    :param items: The items to split.
    :param size: The maximum chunk length.
    :return: The chunks.
    """
    return [items[start : start + size] for start in range(0, len(items), max(size, 1))]


def _read_batch(
    age_payload: Any,
    value_payload: Any,
    by_external_id: dict[str, ServiceKey],
    signals: Sequence[Signal],
    *,
    reference: datetime,
    max_age_seconds: int,
) -> tuple[list[Fact], set[str], set[str], float | None]:
    """Turn one metric's query responses into facts, plus the coverage they evidence.

    :param age_payload: The decoded :data:`AGE_TEMPLATE` response; its sample value is
        the age in seconds of the series' last raw sample.
    :param value_payload: The decoded :data:`VALUE_TEMPLATE` response, or ``None`` when
        no signal on this metric reads the sample value.
    :param by_external_id: The live services, keyed by PMM service UUID.
    :param signals: The signals reading from this metric.
    :param reference: The time observation timestamps are measured back from.
    :param max_age_seconds: Above this, a service counts as stale.
    :return: The facts, the services covered, the services whose sample was stale, and
        the oldest sample age seen, or ``None`` when no series was readable.
    """
    facts: list[Fact] = []
    covered: set[str] = set()
    stale: set[str] = set()
    oldest_age: float | None = None
    # Candidates for reducing signals, buffered across the series loop because the fold
    # can only run once every series for a service has been seen.
    pending: dict[tuple[str, str], list[tuple[Any, datetime]]] = {}

    values = {
        _join_key(labels): value for labels, value in parse_series(value_payload or {})
    }

    # An expression signal has no age query, so the value response is what enumerates
    # the services and every reading is dated to the run. Treating that as age 0 keeps
    # one loop rather than two, and is honest: the sample is as fresh as the query.
    driving = (
        parse_series(age_payload)
        if age_payload is not None
        else [(labels, 0.0) for labels, _ in parse_series(value_payload or {})]
    )

    for labels, age in driving:
        service = by_external_id.get(labels.get("service_id", ""))
        if service is None:
            # A series belonging to a generation inventory no longer lists. The pinned
            # matcher makes this unreachable today; it stays as a guard, because the
            # alternative is silently attributing a dead node's facts to a live row.
            continue
        observed_at = reference - timedelta(seconds=age)
        oldest_age = age if oldest_age is None else max(oldest_age, age)
        if age > max_age_seconds:
            stale.add(service.key)
        covered.add(service.key)
        sample_value = values.get(_join_key(labels), 0.0)
        for signal in signals:
            value = signal.take.extract(labels, sample_value)
            if value is None or value == "":
                continue
            if signal.reduce is not None:
                pending.setdefault((service.key, signal.field), []).append(
                    (value, observed_at)
                )
                continue
            facts.append(
                Fact(
                    service=service.key,
                    field=signal.field,
                    value=value,
                    source=SOURCE_KEY,
                    observed_at=observed_at,
                )
            )

    facts.extend(_reduced_facts(pending, signals))
    return facts, covered, stale, oldest_age


def _reduced_facts(
    pending: dict[tuple[str, str], list[tuple[Any, datetime]]],
    signals: Sequence[Signal],
) -> list[Fact]:
    """Fold each reducing signal's buffered series into one fact per service.

    The emitted ``observed_at`` is the winning series' own, not the newest or the oldest
    of the group: a fact must be able to say when *the value it carries* was observed,
    or the staleness rules downstream would be reasoning about a different sample.

    :param pending: Buffered ``(value, observed_at)`` per ``(service, field)``.
    :param signals: The signals read from this metric, for their reducers.
    :return: One fact per buffered ``(service, field)``.
    """
    reducers = {s.field: s.reduce for s in signals if s.reduce is not None}
    facts: list[Fact] = []
    for (service, field), candidates in pending.items():
        reduce = reducers.get(field)
        if reduce is None or not candidates:
            continue
        try:
            winner = reduce([value for value, _ in candidates])
        except (TypeError, ValueError) as err:  # a reducer must not fail the run
            logger.warning(
                "POM discovery: reducing %s for service %s failed: %s",
                field,
                service,
                err,
            )
            continue
        observed_at = next(
            (at for value, at in candidates if value == winner), candidates[0][1]
        )
        facts.append(
            Fact(
                service=service,
                field=field,
                value=winner,
                source=SOURCE_KEY,
                observed_at=observed_at,
            )
        )
    return facts


async def collect_metric_facts(
    pmm_api: PMMRemoteAPI,
    services: Sequence[ServiceKey],
    signals: Sequence[Signal],
    *,
    lookback: str,
    max_age_seconds: int,
    batch_size: int,
    now: datetime | None = None,
) -> SourceResult:
    """Query VictoriaMetrics for ``signals`` and return them as facts.

    One query per distinct metric per batch of services -- **not** one per signal. The
    catalog's nine signals read from two metrics, so a sandbox-sized estate costs two
    round trips however far the catalog grows within those metrics.

    Stale samples are **kept**, not discarded: the fact carries its ``observed_at`` and
    the count of stale services lands in the result detail. Dropping them would erase
    the difference between "this service is gone" and "this service has not been scraped
    since Tuesday", which is exactly the distinction the health job will need.

    :param pmm_api: The PMM client; carries the credentials VM sits behind.
    :param services: The services to ask about. Those without an ``external_id`` are
        skipped and counted, since there is nothing to pin a query to.
    :param signals: The enabled catalog signals.
    :param lookback: The ``last_over_time`` window.
    :param max_age_seconds: Above this, a sample is counted stale in the detail.
    :param batch_size: Services per query.
    :param now: Reference time for staleness; defaults to the current UTC time.
    :return: The facts, a status, and the detail recorded on the run.
    """
    reference = now or datetime.now(UTC)
    by_external_id = {s.external_id: s for s in services if s.external_id}
    skipped = len(services) - len(by_external_id)

    grouped = by_metric(signals)
    detail: dict[str, Any] = {
        "queries": sorted(grouped),
        "services_requested": len(services),
        "services_without_external_id": skipped,
        "services_covered": 0,
        "facts": 0,
        "stale_services": 0,
        "oldest_sample_age_seconds": None,
        "errors": [],
    }

    if not by_external_id or not grouped:
        detail["errors"].append(
            "no services carry a PMM service id"
            if not by_external_id
            else "no metric signals are enabled"
        )
        return SourceResult(SOURCE_KEY, SourceStatus.FAILED, (), detail)

    facts: list[Fact] = []
    covered: set[str] = set()
    stale: set[str] = set()
    oldest_age: float | None = None
    external_ids = sorted(by_external_id)

    for metric, metric_signals in grouped.items():
        # An expression signal carries its own PromQL and is value-only: `lag()` has no
        # meaning over an aggregation, so there is no age query to pair with it and its
        # facts are dated to the run instead of to a sample.
        expression = next((s.query for s in metric_signals if s.query), None)
        # Otherwise the value query is issued only when a signal on this metric actually
        # reads the sample value, because `lag`'s value is the age, not the metric's own.
        needs_value = any(isinstance(s.take, Value) for s in metric_signals)
        for batch in _chunks(external_ids, batch_size):
            try:
                if expression is not None:
                    age_payload = None
                    value_payload = await pmm_api.get(
                        QUERY_PATH,
                        params={"query": build_expression_query(expression, batch)},
                    )
                else:
                    age_payload = await pmm_api.get(
                        QUERY_PATH,
                        params={
                            "query": build_query(metric, batch, lookback, AGE_TEMPLATE)
                        },
                    )
                    value_payload = (
                        await pmm_api.get(
                            QUERY_PATH,
                            params={
                                "query": build_query(
                                    metric, batch, lookback, VALUE_TEMPLATE
                                )
                            },
                        )
                        if needs_value
                        else None
                    )
            except Exception as err:  # noqa: BLE001 - one metric must not lose the rest
                message = f"{metric}: {type(err).__name__}: {err}"
                logger.warning("POM discovery: metrics query failed -- %s", message)
                detail["errors"].append(message)
                continue

            batch_facts, batch_covered, batch_stale, batch_oldest = _read_batch(
                age_payload,
                value_payload,
                by_external_id,
                metric_signals,
                reference=reference,
                max_age_seconds=max_age_seconds,
            )
            facts.extend(batch_facts)
            covered |= batch_covered
            stale |= batch_stale
            if batch_oldest is not None:
                oldest_age = (
                    batch_oldest
                    if oldest_age is None
                    else max(oldest_age, batch_oldest)
                )

    detail["services_covered"] = len(covered)
    detail["facts"] = len(facts)
    detail["stale_services"] = len(stale)
    detail["oldest_sample_age_seconds"] = (
        None if oldest_age is None else round(oldest_age)
    )

    # Measured against every service *asked about*, not just the ones that carried a
    # PMM id. A service with no ``external_id`` is one this source structurally cannot
    # answer for, and counting it out of the denominator would report a clean OK on a
    # run that silently knows nothing about part of the estate.
    if covered and len(covered) == len(services) and not detail["errors"]:
        status = SourceStatus.OK
    elif covered:
        status = SourceStatus.PARTIAL
    else:
        status = SourceStatus.FAILED

    logger.info(
        "POM discovery: metrics covered %d/%d service(s), %d fact(s), %d stale",
        len(covered),
        len(services),
        len(facts),
        len(stale),
    )
    return SourceResult(SOURCE_KEY, status, tuple(facts), detail)
