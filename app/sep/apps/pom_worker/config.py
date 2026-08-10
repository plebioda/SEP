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

"""Define the POM worker settings section.

Read straight off YAML/env under ``SEP.POM_WORKER`` rather than mounted as a field
on ``SEPSettings``, for the same reason ``atw`` does it: importing this module runs
the package ``__init__``, which pulls in the app definition and transitively
``sep_settings``, so a field default typed with this class would cycle while
``SEPSettings`` is still under construction. Consumers import :data:`pom_worker_settings`
at call time.
"""

__all__ = ["PomWorkerSettings", "pom_worker_settings"]

from datetime import timedelta
from typing import Annotated, ClassVar

from annotated_types import Gt
from pydantic import PositiveInt

from app.core.celery.models import IntervalSchedule, Period
from app.core.config import BaseYamlSettings
from app.core.utils.fields import TimedeltaSeconds


class PomWorkerSettings(BaseYamlSettings):
    """Configure the POM worker collection job.

    :cvar SETTINGS_PREFIXES: Places this section under ``SEP.POM_WORKER``.
    :param EMIT_METRICS: Master switch for VictoriaMetrics emission. When false the
        job still maps and probes and persists to Postgres, and writes nothing to VM.
    :param EMIT_RAW_JSON: Whether to additionally emit the chunked
        ``pom_result`` series carrying the raw probe JSON. Requires
        ``EMIT_METRICS``; kept separate because it is the expensive, high-cardinality
        one and is only useful for eyeballing a run in vmui.
    :param PROBE_DATABASE: Whether the payload connects to mongod and runs database
        commands. False collects process and OS facts only, which needs no
        credentials.
    :param CREDENTIALS_PATH: Node-side file holding the MongoDB URI to take
        credentials from. ``None`` lets the payload fall back to ``~/.mongodb_uri``,
        the same file the PBM payloads read.
    :param CONNECT_TIMEOUT: Per-target connect and server-selection timeout, seconds.
    :param TASK_TIMEOUT: How long to wait for one dispatched probe task to reach a
        terminal status before giving up on it, seconds.
    :param POLL_INTERVAL: Delay between task-status polls, seconds.
    :param MAX_CONCURRENT_PROBES: Ceiling on probe tasks in flight at once. The
        sandbox has 12 executors; a real estate has many more, and every dispatch is
        a Nomad job.
    :param SOURCES: Which discovery sources run. Dropping ``probe`` yields a complete
        status document with **no Nomad dependency at all** -- worth knowing, because
        the probe reaches only services with a healthy ``raw_exec`` executor while the
        metrics source reaches every service PMM monitors, which in this workspace is
        1 against 38.
    :param METRICS_GROUPS: Which groups of
        :data:`~app.sep.apps.pom_worker.metrics_catalog.SIGNALS` are collected. One
        query is issued per distinct metric across the enabled groups, so this is a
        cost dial as well as a content one.
    :param METRICS_LOOKBACK: The ``last_over_time`` window wrapped around every query.
        Instant queries look back only five minutes, so an unwrapped query returns
        nothing whenever scraping paused; this is what stops that reading as "no such
        service".
    :param METRICS_MAX_AGE: Seconds beyond which a sample is *counted* stale on the
        run. Deliberately not a filter -- stale facts are kept, with their age, because
        discarding them erases the difference between "this service is gone" and "this
        service has not been scraped since Tuesday".
    :param METRICS_QUERY_BATCH: Services pinned per query. Each contributes a 37-byte
        UUID to a regex matcher, so this bounds the query string rather than the
        result set.
    :param STALE_RUN_AFTER: How long a run may stay ``RUNNING`` before the sweep
        concludes its worker is gone and fails it. Must comfortably exceed the slowest
        legitimate run, or a healthy collection is failed mid-flight while it is still
        probing -- the ceiling on that is ``TASK_TIMEOUT`` per dispatched task, with
        ``MAX_CONCURRENT_PROBES`` in flight at a time. The trigger endpoint reads the
        same value, so a ``RUNNING`` row is refused a concurrent trigger and swept by
        the same clock.
    :param STALE_SWEEP_INTERVAL: Cadence of the ``reap_stale_pom_runs`` sweep.
        ``None`` unregisters it entirely, which leaves the trigger endpoint as the
        only thing that reaps -- and a stranded run then keeps the UI's Sync button
        disabled until someone calls the endpoint some other way.
    """

    SETTINGS_PREFIXES: ClassVar[list[str]] = ["SEP", "POM_WORKER"]

    EMIT_METRICS: bool = False
    EMIT_RAW_JSON: bool = False
    PROBE_DATABASE: bool = True
    CREDENTIALS_PATH: str | None = None
    CONNECT_TIMEOUT: PositiveInt = 5
    TASK_TIMEOUT: PositiveInt = 180
    POLL_INTERVAL: PositiveInt = 3
    MAX_CONCURRENT_PROBES: PositiveInt = 8
    SOURCES: list[str] = ["inventory", "metrics", "probe"]
    METRICS_GROUPS: list[str] = [
        "identity",
        "rs_status",
        "replication",
        "health",
        "sharding",
    ]
    METRICS_LOOKBACK: str = "24h"
    METRICS_MAX_AGE: PositiveInt = 300
    METRICS_QUERY_BATCH: PositiveInt = 50
    STALE_RUN_AFTER: Annotated[TimedeltaSeconds, Gt(timedelta(0))] = timedelta(
        minutes=30
    )
    STALE_SWEEP_INTERVAL: IntervalSchedule | None = IntervalSchedule(
        every=5, period=Period.MINUTES
    )


pom_worker_settings: PomWorkerSettings = PomWorkerSettings()
