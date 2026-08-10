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

"""Define the POM worker Celery entry point.

``@owned_by("pom_worker")`` tags the task so the app-drain reconciler counts it
toward this app rather than treating it as a core task. The module is included in
the worker's ``include`` list because the app is registered in ``SEP.APPS`` and the
registry derives the Celery module path from the package's ``celery.py``.
"""

import logging
from uuid import UUID

from app.celery import celery
from app.sep.app_drain import owned_by
from app.sep.apps.pom_worker.config import pom_worker_settings
from app.sep.apps.pom_worker.reap import sweep_stale_runs
from app.sep.apps.pom_worker.service import run_discovery

logger = logging.getLogger(__name__)


@owned_by("pom_worker")
@celery.task
def run_pom_discovery(execution_id: str | None = None) -> str:
    """Run one POM worker collection and return its execution id.

    The returned id is the ``execution_id`` label on every emitted VictoriaMetrics
    series and the primary key of the ``pom_run`` row, so it is the handle for
    inspecting the run from either side.

    :param execution_id: An already-created run's id, passed by the API's trigger
        endpoint so the caller could be answered before the work began. ``None``
        mints a fresh run.
    :return: The run's execution id, as a string.
    """
    resolved = celery.loop.run_until_complete(
        run_discovery(UUID(execution_id) if execution_id else None)
    )
    return str(resolved)


@owned_by("pom_worker")
@celery.task
def reap_stale_pom_runs() -> int:
    """Fail discovery runs whose worker never recorded a terminal status.

    Scheduled by this app's ``periodic_task_schedules`` contribution. Nothing else
    advances such a row, and both the trigger endpoint and the UI's Sync button treat
    it as a live run, so without this sweep one lost worker wedges discovery until
    someone intervenes by hand.

    :return: The number of runs failed.
    """
    return len(
        celery.loop.run_until_complete(
            sweep_stale_runs(pom_worker_settings.STALE_RUN_AFTER)
        )
    )
