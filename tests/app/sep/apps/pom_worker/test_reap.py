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

"""Test the sweep that fails discovery runs abandoned by a lost worker.

A stranded ``RUNNING`` row is a deadlock, not merely stale data: the trigger endpoint
refuses a concurrent run while one exists, and the UI disables its Sync button while
the newest run is non-terminal -- so the row disables the only control that used to
reap it. These tests pin the two halves that matter: an aged row is driven to a
terminal status, and a young or already-finished one is left strictly alone.
"""

from datetime import timedelta
from typing import cast

import pytest
import pytest_asyncio
from pydantic import ValidationError
from pytest_mock import MockerFixture
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from app.core.celery.models import IntervalSchedule
from app.core.db.utils import get_async_session_maker_from_engine
from app.core.utils import json_serializer
from app.core.utils.date_time import utc_now
from app.sep.apps.pom_worker.app import _pom_worker_periodic_tasks
from app.sep.apps.pom_worker.config import pom_worker_settings, PomWorkerSettings
from app.sep.apps.pom_worker.crud import PomRunManager
from app.sep.apps.pom_worker.models import PomRun, PomRunStatus
from app.sep.apps.pom_worker.reap import STALE_RUN_ERROR, sweep_stale_runs

#: The staleness window every case is measured against.
STALE_AFTER = timedelta(minutes=30)
#: Runs seeded stranded in the multi-row cases.
STRANDED_RUN_COUNT = 2


@pytest_asyncio.fixture(name="run_session")
async def run_session_fixture(mocker: MockerFixture) -> AsyncSession:
    """Yield a session over an empty in-memory schema.

    The sweep opens a session of its own, so the maker it reaches for is pointed at
    this test engine; assertions then read rows back through *this* session, which is
    what proves the update committed rather than living on an in-flight instance.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        json_serializer=json_serializer,
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_maker = get_async_session_maker_from_engine(engine)
    mocker.patch(
        "app.sep.apps.pom_worker.reap.get_async_session_maker",
        return_value=session_maker,
    )
    try:
        async with session_maker() as session:
            yield session
    finally:
        await engine.dispose()


async def seed_run(
    session: AsyncSession,
    *,
    status: PomRunStatus = PomRunStatus.RUNNING,
    age: timedelta = timedelta(0),
) -> PomRun:
    """Persist one run at a chosen status and age.

    :param session: The session to write through.
    :param status: The run's stored status.
    :param age: How long ago the run started.
    :return: The persisted run.
    """
    return await PomRunManager.save(
        session, PomRun(status=status, started_at=utc_now() - age)
    )


@pytest.mark.asyncio
class TestSweepStaleRuns:
    """Cover the conditional update behind both reapers."""

    async def test_fails_a_run_aged_past_the_cutoff(
        self, run_session: AsyncSession
    ) -> None:
        """Drive a run whose worker never came back to a terminal status."""
        run = await seed_run(run_session, age=timedelta(days=2))

        reaped = await sweep_stale_runs(STALE_AFTER)

        run_session.expunge_all()
        reloaded = await PomRunManager.get(run_session, id=run.id)
        assert reaped == [run.id]
        assert reloaded.status is PomRunStatus.FAILED
        assert reloaded.finished_at is not None
        assert reloaded.error == STALE_RUN_ERROR

    async def test_leaves_a_young_run_alone(self, run_session: AsyncSession) -> None:
        """Spare a run that is still plausibly executing.

        The cutoff is a guess about a dead process, so a run inside it must survive --
        failing one mid-probe would report a healthy collection as broken.
        """
        run = await seed_run(run_session, age=timedelta(minutes=1))

        reaped = await sweep_stale_runs(STALE_AFTER)

        run_session.expunge_all()
        reloaded = await PomRunManager.get(run_session, id=run.id)
        assert reaped == []
        assert reloaded.status is PomRunStatus.RUNNING
        assert reloaded.finished_at is None

    @pytest.mark.parametrize(
        "status", [PomRunStatus.SUCCESS, PomRunStatus.PARTIAL, PomRunStatus.FAILED]
    )
    async def test_leaves_terminal_runs_alone(
        self, run_session: AsyncSession, status: PomRunStatus
    ) -> None:
        """Never rewrite a run that already reached a terminal status.

        Every historical row is older than any cutoff, so the ``RUNNING`` predicate is
        the only thing standing between the sweep and stamping the whole run history
        with an abandonment error.
        """
        run = await seed_run(run_session, status=status, age=timedelta(days=2))

        reaped = await sweep_stale_runs(STALE_AFTER)

        run_session.expunge_all()
        reloaded = await PomRunManager.get(run_session, id=run.id)
        assert reaped == []
        assert reloaded.status is status
        assert reloaded.error is None

    async def test_fails_every_stranded_run_not_just_the_newest(
        self, run_session: AsyncSession
    ) -> None:
        """Sweep the whole backlog a restarted or duplicated backend can leave."""
        older = await seed_run(run_session, age=timedelta(days=3))
        newer = await seed_run(run_session, age=timedelta(days=1))

        reaped = await sweep_stale_runs(STALE_AFTER)

        assert len(reaped) == STRANDED_RUN_COUNT
        assert set(reaped) == {older.id, newer.id}

    async def test_reaps_only_the_aged_rows_of_a_mixed_table(
        self, run_session: AsyncSession
    ) -> None:
        """Pick the stranded rows out of a table that also holds live and done ones."""
        stranded = await seed_run(run_session, age=timedelta(days=2))
        live = await seed_run(run_session, age=timedelta(minutes=2))
        done = await seed_run(
            run_session, status=PomRunStatus.SUCCESS, age=timedelta(days=5)
        )

        reaped = await sweep_stale_runs(STALE_AFTER)

        assert reaped == [stranded.id]
        assert live.id not in reaped
        assert done.id not in reaped

    async def test_reports_nothing_on_an_empty_table(
        self, run_session: AsyncSession
    ) -> None:
        """Answer cleanly when there is no run at all to consider."""
        assert await sweep_stale_runs(STALE_AFTER) == []

    async def test_a_second_sweep_is_a_no_op(self, run_session: AsyncSession) -> None:
        """Reap each stranded run exactly once.

        The beat schedule fires on a cadence far shorter than the cutoff, so nearly
        every sweep runs over rows a previous one already failed.
        """
        run = await seed_run(run_session, age=timedelta(days=2))

        first = await sweep_stale_runs(STALE_AFTER)
        second = await sweep_stale_runs(STALE_AFTER)

        assert first == [run.id]
        assert second == []


class TestPeriodicContribution:
    """Cover the beat schedule the app contributes for the sweep."""

    def test_contributes_the_sweep_by_default(self) -> None:
        """Ensure a stock deployment schedules the reaper without configuration."""
        contributed = _pom_worker_periodic_tasks()

        assert [spec.name for spec in contributed] == ["sep__reap_stale_pom_runs"]
        assert contributed[0].task == "reap_stale_pom_runs"
        assert isinstance(contributed[0].schedule(), IntervalSchedule)

    def test_reads_the_interval_at_seed_time(self, mocker: MockerFixture) -> None:
        """Ensure a hot interval override is picked up rather than frozen at import."""
        override = IntervalSchedule(every=1, period="minutes")
        mocker.patch.object(
            pom_worker_settings,
            "STALE_SWEEP_INTERVAL",
            cast(IntervalSchedule, override),
        )

        assert _pom_worker_periodic_tasks()[0].schedule() == override

    def test_contributes_nothing_when_the_sweep_is_disabled(
        self, mocker: MockerFixture
    ) -> None:
        """Ensure an operator can switch the sweep off entirely."""
        mocker.patch.object(pom_worker_settings, "STALE_SWEEP_INTERVAL", None)

        assert _pom_worker_periodic_tasks() == []


class TestStaleRunSettings:
    """Cover the bounds on the two knobs the sweep reads."""

    def test_defaults_schedule_a_sweep_with_a_positive_cutoff(self) -> None:
        """Ensure the shipped section reaps without any configuration."""
        pom = PomWorkerSettings()

        assert pom.STALE_SWEEP_INTERVAL is not None
        assert timedelta(0) < pom.STALE_RUN_AFTER

    def test_sweeps_more_often_than_the_cutoff(self) -> None:
        """Keep the cadence short enough that a stranded run is reaped promptly.

        A sweep slower than the cutoff would leave a run stranded for up to one whole
        interval past the point it was known dead, which is the wedged UI this exists
        to prevent.
        """
        pom = PomWorkerSettings()
        interval = cast(IntervalSchedule, pom.STALE_SWEEP_INTERVAL)

        assert timedelta(**{interval.period: interval.every}) < pom.STALE_RUN_AFTER

    @pytest.mark.parametrize("value", [timedelta(0), timedelta(seconds=-1)])
    def test_rejects_a_non_positive_cutoff(self, value: timedelta) -> None:
        """Ensure a cutoff that would fail every in-flight run is refused at load."""
        with pytest.raises(ValidationError):
            PomWorkerSettings(STALE_RUN_AFTER=value)

    def test_the_sweep_may_be_disabled(self) -> None:
        """Ensure the schedule can be unregistered through configuration."""
        assert PomWorkerSettings(STALE_SWEEP_INTERVAL=None).STALE_SWEEP_INTERVAL is None
