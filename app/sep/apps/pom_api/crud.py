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

"""Read the worker's snapshot tables.

This app owns no tables. It reads what ``pom_worker`` wrote, which is the whole
point of the split: collection and presentation change independently.

**Snapshot atomicity** is enforced here rather than in the worker. A run's rows are
committed in one transaction together with its terminal status, so selecting the
newest run whose status is *terminal* can only ever see a complete snapshot -- a run
still in progress is invisible to readers no matter how far along its writes are.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.sep.apps.pom_worker.models import PomCluster, PomRun, PomRunStatus

#: Run states whose snapshot a reader may see. ``FAILED`` is included deliberately:
#: a failed run still recorded which services exist and that none could be reached,
#: which is a truthful -- and useful -- snapshot. Only ``RUNNING`` is excluded.
TERMINAL_STATUSES = (PomRunStatus.SUCCESS, PomRunStatus.PARTIAL, PomRunStatus.FAILED)


async def latest_snapshot_run(session: AsyncSession) -> PomRun | None:
    """Return the newest run whose snapshot is complete.

    :param session: The database session.
    :return: The run, or ``None`` when no discovery has ever finished.
    """
    result = await session.exec(
        select(PomRun)
        .where(PomRun.status.in_(TERMINAL_STATUSES))  # type: ignore[attr-defined]
        .order_by(PomRun.started_at.desc())  # type: ignore[attr-defined]
        .limit(1)
    )
    return result.first()


async def clusters_for_run(session: AsyncSession, run_id: UUID) -> list[PomCluster]:
    """Return every cluster belonging to one run, ordered by name.

    :param session: The database session.
    :param run_id: The run whose snapshot to read.
    :return: The cluster rows.
    """
    result = await session.exec(
        select(PomCluster).where(PomCluster.run_id == run_id).order_by(PomCluster.name)  # type: ignore[arg-type]
    )
    return list(result.all())


async def cluster_for_run(
    session: AsyncSession, run_id: UUID, cluster_id: str
) -> PomCluster | None:
    """Return one cluster from a run's snapshot.

    A keyed lookup rather than a JSON path extraction, which is why the worker
    stores one row per cluster rather than one document per run.

    :param session: The database session.
    :param run_id: The run whose snapshot to read.
    :param cluster_id: The opaque cluster id.
    :return: The cluster row, or ``None`` when the snapshot has no such cluster.
    """
    result = await session.exec(
        select(PomCluster).where(
            PomCluster.run_id == run_id, PomCluster.cluster_id == cluster_id
        )
    )
    return result.first()


async def recent_runs(session: AsyncSession, limit: int = 20) -> list[PomRun]:
    """Return recent discovery runs, newest first.

    :param session: The database session.
    :param limit: How many to return.
    :return: The runs.
    """
    result = await session.exec(
        select(PomRun).order_by(PomRun.started_at.desc()).limit(limit)  # type: ignore[attr-defined]
    )
    return list(result.all())


async def get_run(session: AsyncSession, run_id: UUID) -> PomRun | None:
    """Return one run by id.

    :param session: The database session.
    :param run_id: The run to fetch.
    :return: The run, or ``None`` when unknown.
    """
    result = await session.exec(select(PomRun).where(PomRun.id == run_id))
    return result.first()


async def running_run(session: AsyncSession) -> PomRun | None:
    """Return a discovery run that is currently in flight, if any.

    Used to refuse a concurrent trigger. Note that a run whose process died leaves
    its row ``RUNNING`` forever, which would wedge the trigger permanently -- the
    caller pairs this with a staleness cutoff rather than trusting the status alone.

    :param session: The database session.
    :return: The in-flight run, or ``None``.
    """
    result = await session.exec(
        select(PomRun)
        .where(PomRun.status == PomRunStatus.RUNNING)
        .order_by(PomRun.started_at.desc())  # type: ignore[attr-defined]
        .limit(1)
    )
    return result.first()
