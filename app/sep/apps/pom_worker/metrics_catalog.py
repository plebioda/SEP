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

"""Declare which VictoriaMetrics series discovery reads, and what each supplies.

This table **is** the configuration. Adding a field to the status document is one
:class:`Signal` entry here; nothing else changes, because
:mod:`~app.sep.apps.pom_worker.metrics_source` groups signals by metric and issues one
query per distinct metric however many signals read from it. Nine signals below cost
**two** HTTP round trips.

Two facts about PMM's mongodb_exporter make this table short, and both were measured
against a live VictoriaMetrics:

* **Every ``mongodb_*`` series carries the full identity label set** -- ``service_id``,
  ``service_name``, ``service_type``, ``node_name``, ``node_id``, ``cluster``,
  ``replication_set``, ``environment``, ``agent_id``, ``machine_id``. So identity is
  free on whatever series you were already fetching.
* **``mongodb_version_info`` is an info metric**: its value is always ``1`` and its
  payload is entirely in three labels -- ``mongodb`` (the running version), ``vendor``
  and ``edition``. It is the only source of ``vendor`` and ``edition`` anywhere; the
  Nomad probe collects neither.

.. warning::
   **Never add a wildcard signal.** ``mongodb_ss_*`` -- serverStatus -- is **6362
   series for a single service**, measured, out of 6046 distinct ``mongodb_*`` metric
   names. A ``mongodb_ss_.*`` matcher is roughly 360000 series across a 38-service
   estate. Health rules that want serverStatus leaves must name them in full,
   one :class:`Signal` each.
"""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "GROUP_IDENTITY",
    "GROUP_RS_STATUS",
    "MEMBERS_SELF",
    "SIGNALS",
    "VERSION_INFO",
    "Label",
    "Signal",
    "Value",
    "by_metric",
    "known_groups",
    "signals_for",
]

#: The exporter's info metric: identity, running version, vendor and edition.
VERSION_INFO = "mongodb_version_info"
#: ``replSetGetStatus`` as seen from the member itself -- its own ``member_state``.
#: The sibling ``mongodb_rs_members_state`` carries one series *per peer* and is what a
#: health rule wants; this one is a single series describing the node being asked.
MEMBERS_SELF = "mongodb_members_self"

#: Signal groups, each independently switchable via ``SEP.POM_WORKER.METRICS_GROUPS``.
GROUP_IDENTITY = "identity"
GROUP_RS_STATUS = "rs_status"


@dataclass(frozen=True, slots=True)
class Label:
    """Take a signal's value from one of the series' labels.

    The common case here: everything the status document needs is carried as a label,
    and the sample value is only evidence that the series exists at all.

    :param name: The label to read.
    """

    name: str

    # ``value`` is unused here and ``labels`` is unused on Value: the two takers share
    # one signature so the collector can call either without knowing which it holds.
    def extract(self, labels: dict[str, str], value: float) -> Any:  # noqa: ARG002
        """Return the label's value.

        :param labels: The series' labels.
        :param value: The sample value, unused.
        :return: The label value, or ``None`` when the label is absent.
        """
        return labels.get(self.name)


@dataclass(frozen=True, slots=True)
class Value:
    """Take a signal's value from the sample itself.

    Unused by the discovery catalog -- every field the document needs is a label -- and
    present because the health job will need it for lag, oplog windows and counters.

    :param cast: Applied to the raw float, e.g. :class:`int` or :class:`bool`.
    """

    cast: Callable[[float], Any] = float

    def extract(self, labels: dict[str, str], value: float) -> Any:  # noqa: ARG002
        """Return the cast sample value.

        :param labels: The series' labels, unused.
        :param value: The sample value.
        :return: The cast value, or ``None`` when casting fails.
        """
        try:
            return self.cast(value)
        except (TypeError, ValueError):
            return None


@dataclass(frozen=True, slots=True)
class Signal:
    """Map one status-document field onto one VictoriaMetrics series.

    :param field: The document field this fills, e.g. ``version``.
    :param metric: The **bare metric name** to query. Deliberately not a free-form
        PromQL expression: the collector appends a ``{service_id=~"..."}`` matcher
        pinning the query to the live service set, and appending a matcher to an
        arbitrary expression is not generally valid. An arithmetic signal -- an oplog
        window, say -- needs an explicit escape hatch added here first.
    :param take: How to read the value: :class:`Label` or :class:`Value`.
    :param group: The switchable group this belongs to.
    """

    field: str
    metric: str
    take: Label | Value
    group: str


#: Exactly the signals the status document requires -- nothing speculative. Between
#: them these two metrics supply nine of its ten service fields; the tenth,
#: ``endpoint``, has no VictoriaMetrics label anywhere and comes from inventory.
SIGNALS: tuple[Signal, ...] = (
    # -- mongodb_version_info: identity, versions, provenance -------------------
    Signal("host", VERSION_INFO, Label("node_name"), GROUP_IDENTITY),
    Signal("service_type", VERSION_INFO, Label("service_type"), GROUP_IDENTITY),
    Signal("cluster", VERSION_INFO, Label("cluster"), GROUP_IDENTITY),
    Signal("replication_set", VERSION_INFO, Label("replication_set"), GROUP_IDENTITY),
    Signal("environment", VERSION_INFO, Label("environment"), GROUP_IDENTITY),
    Signal("version", VERSION_INFO, Label("mongodb"), GROUP_IDENTITY),
    Signal("vendor", VERSION_INFO, Label("vendor"), GROUP_IDENTITY),
    Signal("edition", VERSION_INFO, Label("edition"), GROUP_IDENTITY),
    # -- mongodb_members_self: this node's own replica-set state ----------------
    Signal("state", MEMBERS_SELF, Label("member_state"), GROUP_RS_STATUS),
)


def known_groups(signals: Sequence[Signal] = SIGNALS) -> set[str]:
    """Return every group named in the catalog.

    :param signals: The catalog to inspect.
    :return: The group names.
    """
    return {signal.group for signal in signals}


def signals_for(
    groups: Iterable[str], signals: Sequence[Signal] = SIGNALS
) -> tuple[Signal, ...]:
    """Return the signals belonging to any of ``groups``, in catalog order.

    :param groups: The enabled group names.
    :param signals: The catalog to filter.
    :return: The enabled signals.
    """
    enabled = set(groups)
    return tuple(signal for signal in signals if signal.group in enabled)


def by_metric(signals: Sequence[Signal]) -> dict[str, tuple[Signal, ...]]:
    """Group signals by the metric they read, preserving catalog order.

    This is what keeps the catalog free to grow: the collector issues one query per
    key of this mapping, not one per signal.

    :param signals: The enabled signals.
    :return: ``{metric_name: signals reading it}``.
    """
    grouped: dict[str, list[Signal]] = {}
    for signal in signals:
        grouped.setdefault(signal.metric, []).append(signal)
    return {metric: tuple(items) for metric, items in grouped.items()}
