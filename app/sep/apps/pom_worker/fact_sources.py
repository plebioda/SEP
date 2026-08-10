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

"""Turn the two non-metric sources into facts.

Inventory and the Nomad probe are already collected by the run; these functions only
restate what they produced in the common
:class:`~app.sep.apps.pom_worker.facts.Fact` currency, so all three sources merge by
one set of rules rather than three special cases.

Pure -- no I/O, no SEP clients, no database -- so the whole projection path is testable
from plain dictionaries. The VictoriaMetrics source is the one that must talk to
something, and it lives in :mod:`~app.sep.apps.pom_worker.metrics_source`.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from app.sep.apps.pom_worker.facts import Fact, ServiceKey, SourceResult, SourceStatus
from app.sep.apps.pom_worker.inventory import InventoryService
from app.sep.apps.pom_worker.topology import member_state_name

__all__ = [
    "INVENTORY_SOURCE_KEY",
    "PROBE_SOURCE_KEY",
    "inventory_facts",
    "probe_facts",
    "service_keys",
]

INVENTORY_SOURCE_KEY = "inventory"
PROBE_SOURCE_KEY = "probe"


def service_keys(services: Sequence[InventoryService]) -> list[ServiceKey]:
    """Return the join keys for a run's services.

    :param services: The inventory services.
    :return: One :class:`ServiceKey` per service, in order.
    """
    return [
        ServiceKey(
            key=_key(service), name=service.name, external_id=service.external_id
        )
        for service in services
    ]


def _key(service: InventoryService) -> str:
    """Return the fact join key for one service.

    SEP's own inventory id, because ``pom_node`` rows key on it. Falls back to the name
    only when inventory somehow supplied no id, which keeps a nameless run from
    collapsing every service onto one key.

    :param service: The inventory service.
    :return: The join key.
    """
    return str(service.service_id) if service.service_id is not None else service.name


def _endpoint(service: InventoryService) -> str | None:
    """Return the ``host:port`` endpoint for one service.

    Inventory is the only source of this: no VictoriaMetrics label anywhere carries an
    address and port.

    :param service: The inventory service.
    :return: The endpoint, or ``None`` when there is no host to build one from.
    """
    host = service.node_address or service.node_name
    return f"{host}:{service.port}" if host else None


def inventory_facts(services: Sequence[InventoryService]) -> SourceResult:
    """Restate the inventory listing as facts.

    Not time-bounded -- every fact carries ``observed_at=None`` -- because inventory is
    current by definition. That is the distinction :class:`SourceResult` exists to keep:
    an inventory value is never "stale", while a metric sample very much can be.

    :param services: The inventory services.
    :return: The inventory source's result.
    """
    facts: list[Fact] = []
    for service in services:
        key = _key(service)
        for field, value in (
            ("service_name", service.name),
            ("host", service.node_name or service.node_address),
            ("endpoint", _endpoint(service)),
            ("port", service.port),
            ("cluster", service.cluster),
            ("replication_set", service.replication_set),
            ("environment", service.environment),
            ("service_type", "mongodb"),
        ):
            if value is None or value == "":
                continue
            facts.append(Fact(key, field, value, INVENTORY_SOURCE_KEY))

    return SourceResult(
        INVENTORY_SOURCE_KEY,
        SourceStatus.OK if services else SourceStatus.FAILED,
        tuple(facts),
        {
            "services": len(services),
            "services_with_external_id": sum(1 for s in services if s.external_id),
            "facts": len(facts),
        },
    )


def probe_facts(
    records: Mapping[str, dict[str, Any] | None],
    observed_at_by_service: Mapping[str, Any] | None = None,
    *,
    unresolved: int = 0,
) -> SourceResult:
    """Restate the Nomad probe's per-service records as facts.

    The probe contributes the handful of fields nothing else can supply --
    ``installed_version`` above all, which is the *installed* binary as against the
    *running* server the metrics report. Their divergence is the
    upgraded-but-not-restarted case, and it is invisible to VictoriaMetrics.

    Everything else here is a fallback: the precedence table puts metrics first for
    ``version`` and ``state``, so these only surface when the exporter had nothing to
    say about a service.

    :param records: ``{service_key: probe record}`` for services that resolved to an
        executor host; a ``None`` record means the probe was attempted and produced
        nothing.
    :param observed_at_by_service: Optional per-service observation times.
    :param unresolved: Services that never reached the probe because no live executor
        host serves them. Passed separately so "the probe is switched off" stays
        distinguishable from "the probe ran and could not reach a single node" -- the
        second is POM's infrastructure being unavailable, and reporting it as
        ``DISABLED`` would hide exactly the condition the probe exists to surface.
    :return: The probe source's result.
    """
    times = observed_at_by_service or {}
    facts: list[Fact] = []
    answered = 0

    for key, record in records.items():
        if not record:
            continue
        answered += 1
        observed_at = times.get(key)
        database = record.get("database") or {}
        process = record.get("process") or {}
        system = record.get("system") or {}
        for field, value in (
            ("installed_version", record.get("binary_version")),
            ("version", database.get("db_version")),
            ("state", member_state_name(database.get("state"))),
            ("replication_set", database.get("set_name")),
            ("os", system.get("os_name")),
            ("kernel", system.get("kernel")),
            ("server_running", process.get("running")),
            ("server_process", process.get("program")),
            ("uptime_seconds", process.get("uptime_sec")),
            ("config_path", process.get("config_path")),
        ):
            if value is None or value == "":
                continue
            facts.append(Fact(key, field, value, PROBE_SOURCE_KEY, observed_at))

    if not records and not unresolved:
        status = SourceStatus.DISABLED
    elif not answered:
        status = SourceStatus.FAILED
    elif answered == len(records) and not unresolved:
        status = SourceStatus.OK
    else:
        status = SourceStatus.PARTIAL

    return SourceResult(
        PROBE_SOURCE_KEY,
        status,
        tuple(facts),
        {
            "services_attempted": len(records),
            "services_answered": answered,
            "services_unresolved": unresolved,
            "facts": len(facts),
        },
    )
