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

"""Register the POM worker as a minimal ``BaseApp``.

The registration exists for three side effects, not for a user-facing surface:

* the registry derives this package's ``celery.py`` into the worker's ``include``
  list, which is what makes :func:`~app.sep.apps.pom_worker.celery.run_pom_discovery`
  a registered task;
* the app-drain reconciler recognises ``pom_worker`` as an owner key;
* the app appears on the Apps page so collection can be switched off.

It ships no router and no UI: this is a Celery job, driven from a shell or a beat
entry. ``sidebar=False`` keeps it out of the navigation, since there is nothing to
navigate to. The abandoned-run sweep is contributed via ``periodic_task_schedules``.
"""

from typing import cast

from app.core.celery.models import IntervalSchedule
from app.sep.apps.framework.base import AppPeriodicTask, BaseApp
from app.sep.apps.nav_icons import NavIcon
from app.sep.apps.pom_worker.config import pom_worker_settings


def _pom_worker_periodic_tasks() -> list[AppPeriodicTask]:
    """Contribute the abandoned-run sweep while it is configured.

    ``STALE_SWEEP_INTERVAL`` may be ``None`` to unregister the sweep, so this is a
    callable: the contribution is variable-length (0 or 1) and a plain list literal
    would commit to a fixed set at ``BaseApp(...)`` construction.

    Contributed by ``pom_worker`` rather than ``pom_api`` because the schedule is only
    seeded for an app that owns a Celery module, and this is the app whose module the
    worker imports. Disabling ``pom_worker`` therefore stops the sweep along with the
    collection it cleans up after, which is the intended pairing.

    :return: The sweep contrib, or an empty list when the sweep is disabled.
    """
    if pom_worker_settings.STALE_SWEEP_INTERVAL is None:
        return []
    return [
        AppPeriodicTask(
            name="sep__reap_stale_pom_runs",
            task="reap_stale_pom_runs",
            schedule=lambda: cast(
                IntervalSchedule, pom_worker_settings.STALE_SWEEP_INTERVAL
            ),
        ),
    ]


app = BaseApp(
    name="pom_worker",
    display_name="POM Worker",
    uri_path="/pom_worker",
    css_class="pom",
    sidebar=False,
    nav_icon=NavIcon.MONGO,
    periodic_task_schedules=_pom_worker_periodic_tasks,
)
