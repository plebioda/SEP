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

"""Drive discovery runs abandoned by a lost worker to a terminal status.

A ``PomRun`` row is created before the work starts -- by the API trigger so it can
answer ``202`` with an id, or by :func:`~app.sep.apps.pom_worker.service.run_discovery`
itself -- and only the process executing that run ever writes its terminal status. A
worker killed in between leaves the row ``RUNNING`` with nothing that would ever
advance it, and two things then read that row as a live run forever: the trigger
endpoint refuses a concurrent run, and the UI's Sync button stays disabled while the
newest run is non-terminal. That pairing is a deadlock -- the only code that reaps is
behind the one control the stranded row disables -- so the sweep here exists to make
the state self-healing without a client having to ask.

Kept in its own module, deliberately not in ``service.py``: the API imports the reap
helper on the request path, and ``service.py`` pulls in the dispatch, metrics and
inventory stack that the API process otherwise has no reason to load.

The cutoff is a *heuristic about a dead process*, not a run deadline. A run still
executing past it is failed while it works, and will go on to write its own terminal
status afterwards -- so keep ``STALE_RUN_AFTER`` comfortably above the slowest
legitimate run rather than tight enough to feel responsive.
"""

__all__ = ["STALE_RUN_ERROR", "sweep_stale_runs"]

import logging
from datetime import timedelta
from typing import cast
from uuid import UUID

from sqlmodel import col

from app.core.utils.date_time import utc_now
from app.sep.apps.pom_worker.crud import PomRunManager
from app.sep.apps.pom_worker.models import PomRun, PomRunStatus
from app.sep.db import get_async_session_maker

logger = logging.getLogger(__name__)

#: Recorded as the swept run's ``error``. Written by every reaper -- the periodic
#: sweep and the trigger endpoint both route through :func:`sweep_stale_runs` -- so
#: an operator reading run history sees one phrase for "nobody ever finished this",
#: distinct from the exception text a run that genuinely raised carries.
STALE_RUN_ERROR = "abandoned: no completion recorded before the stale cutoff"


async def sweep_stale_runs(stale_after: timedelta) -> list[UUID]:
    """Fail every ``RUNNING`` run that has aged past ``stale_after``.

    One conditional UPDATE rather than a read-then-write loop: the sweep and the
    trigger endpoint can run concurrently against the same row, and the ``status =
    RUNNING`` predicate is what makes the second one a no-op instead of overwriting a
    terminal status a live worker had just written.

    Sweeps every aged row, not just the newest. Normal operation has at most one in
    flight, but a backend restarted mid-run -- or two backends against one database --
    leaves several, and reaping only the newest would keep the older ones as permanent
    ``RUNNING`` rows.

    Opens a session of its own even when the caller holds one, which is why the
    request path pays for a second connection here. A bulk UPDATE makes SQLAlchemy
    re-evaluate the WHERE clause **in Python** against every matching instance in the
    session's identity map, and a ``PomRun`` loaded earlier in the same session
    carries a naive ``started_at`` on any dialect that drops the offset -- comparing
    that to an aware cutoff raises ``TypeError`` from the ORM evaluator rather than
    returning a wrong answer. A fresh session has nothing to evaluate.

    :param stale_after: How long a run may stay ``RUNNING`` before it is failed.
    :return: The ids of the runs failed, empty when none had aged out.
    """
    now = utc_now()
    async_session_maker = get_async_session_maker()
    async with async_session_maker() as session:
        reaped = cast(
            list[UUID],
            await PomRunManager.update_where(
                session,
                {
                    "status": PomRunStatus.FAILED,
                    "finished_at": now,
                    "error": STALE_RUN_ERROR,
                },
                col(PomRun.status) == PomRunStatus.RUNNING,
                col(PomRun.started_at) < now - stale_after,
                returning=["id"],
            ),
        )
    if reaped:
        logger.warning(
            "POM worker: failed %d run(s) with no completion recorded in %s: %s",
            len(reaped),
            stale_after,
            ", ".join(str(run_id) for run_id in reaped),
        )
    return reaped
