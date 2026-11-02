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

"""Test that a scan whose sweep was lost does not hold every later one.

A live sweep writes its run every ``HEARTBEAT_INTERVAL``. A started run that goes
``RUN_LEASE`` without a write lost its sweep, to a worker restart or kill, or to a
PMM Server restart that took the database its failure would have been written to,
and the next scan fails it. A run no worker started is given ``START_WAIT``. A sweep
whose run was failed under it stops.

Every row is refreshed from the database before it is asserted on, so a test sees
what was written rather than what an ORM update painted onto the object in memory.
"""

import asyncio
from collections.abc import Iterator
from contextlib import nullcontext
from datetime import datetime, timedelta, UTC
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlmodel import col
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.utils.date_time import make_datetime_utc, utc_now
from app.extensions.apps.om_inventory import service as service_module
from app.extensions.apps.om_inventory.crud import (
    conflicting_run,
    fail_running_run,
    INTERRUPTED_DETAIL,
    NOT_STARTED_DETAIL,
    ProbeRunManager,
    RUN_LEASE,
    START_WAIT,
    touch_run,
)
from app.extensions.apps.om_inventory.models import ProbeRun, ProbeRunStatus
from app.extensions.apps.om_inventory.service import (
    finalise,
    RunLostError,
    RunProgress,
)
from tests.app.extensions.apps.om_inventory.conftest import CLEAN_OUTCOME

#: Far longer than any run in these tests, so only the lease can reap one.
STALE_AFTER = timedelta(hours=4)
#: Writes to wait for, so a test sees the timer repeat and not only the first one.
BEATS = 3
#: Long enough that a block still waiting on it was stopped from outside.
FOREVER = 60


async def _last_written(session: AsyncSession, run: ProbeRun, when: datetime) -> None:
    """Make ``when`` the run's last write, as a sweep that stopped then would leave it.

    :param session: The database session.
    :param run: The run.
    :param when: Its last write.
    """
    await ProbeRunManager.update_where(
        session, {"updated_at": when}, col(ProbeRun.id) == run.id
    )


async def _stored(session: AsyncSession, run: ProbeRun) -> ProbeRun:
    """Read the run back from the database, not from the session's memory.

    :param session: The database session.
    :param run: The run.
    :return: The run as stored.
    """
    await session.refresh(run)
    return run


async def _assert_reaped_by_the_lease(session: AsyncSession) -> None:
    """Assert a started run silent for longer than the lease is failed, not honoured.

    :param session: The database session.
    """
    run = await ProbeRunManager.save(session, ProbeRun())
    await _last_written(session, run, utc_now() - RUN_LEASE - timedelta(seconds=1))

    assert await conflicting_run(session, None, stale_after=STALE_AFTER) is None

    stored = await _stored(session, run)
    assert (stored.status, stored.error) == (ProbeRunStatus.FAILED, INTERRUPTED_DETAIL)
    assert stored.finished_at is not None


class TestALostRunIsReaped:
    """Fail a running run whose sweep stopped writing it, and only that one."""

    @pytest.mark.asyncio
    async def test_a_run_silent_for_the_lease_is_failed(
        self, session: AsyncSession
    ) -> None:
        """Fail the run and let the new scan through.

        :param session: The database session.
        """
        await _assert_reaped_by_the_lease(session)

    @pytest.mark.postgres
    @pytest.mark.asyncio
    async def test_a_run_silent_for_the_lease_is_failed_on_postgres(
        self, postgres_session: AsyncSession
    ) -> None:
        """Do the same on PostgreSQL.

        :param postgres_session: A session on real PostgreSQL.
        """
        await _assert_reaped_by_the_lease(postgres_session)

    @pytest.mark.asyncio
    async def test_a_run_written_within_the_lease_still_blocks(
        self, session: AsyncSession
    ) -> None:
        """Honour a run whose sweep wrote it inside the lease, however old the run.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(
            session, ProbeRun(started_at=utc_now() - timedelta(hours=1))
        )
        await _last_written(session, run, utc_now() - RUN_LEASE / 2)

        blocking = await conflicting_run(session, None, stale_after=STALE_AFTER)

        assert blocking is not None
        assert blocking.id == run.id

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("waited", "reaped"),
        [
            pytest.param(START_WAIT + timedelta(seconds=1), True, id="past-the-wait"),
            pytest.param(RUN_LEASE + timedelta(seconds=1), False, id="past-the-lease"),
            pytest.param(timedelta(seconds=1), False, id="just-queued"),
        ],
    )
    async def test_a_run_no_worker_started_is_given_the_start_wait(
        self, session: AsyncSession, waited: timedelta, *, reaped: bool
    ) -> None:
        """Wait ``START_WAIT``, not the lease, for a run still queued for a worker.

        Its message outlives a restart of the worker alone and waits while every
        worker process is busy, so the lease alone would drop scans still wanted.

        :param session: The database session.
        :param waited: How long ago it was created.
        :param reaped: Whether it is expected failed.
        """
        run = await ProbeRunManager.save(
            session, ProbeRun(created_at=utc_now() - waited)
        )

        blocking = await conflicting_run(session, None, stale_after=STALE_AFTER)

        assert (blocking is None) is reaped
        stored = await _stored(session, run)
        expected = (
            (ProbeRunStatus.FAILED, NOT_STARTED_DETAIL)
            if reaped
            else (ProbeRunStatus.RUNNING, None)
        )
        assert (stored.status, stored.error) == expected


class TestTouchRun:
    """Mark a run alive only while it is still running, and say which."""

    @pytest.mark.asyncio
    async def test_a_running_run_is_marked_alive(self, session: AsyncSession) -> None:
        """Move the run's last write to now.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(session, ProbeRun())
        await _last_written(session, run, utc_now() - timedelta(hours=1))

        assert await touch_run(session, run.id)

        stored = await _stored(session, run)
        assert stored.updated_at is not None
        assert utc_now() - make_datetime_utc(stored.updated_at) < RUN_LEASE

    @pytest.mark.asyncio
    async def test_a_finished_run_is_left_alone(self, session: AsyncSession) -> None:
        """Leave a run that already reached a terminal status as it is.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(
            session, ProbeRun(status=ProbeRunStatus.FAILED, error=INTERRUPTED_DETAIL)
        )
        an_hour_ago = utc_now() - timedelta(hours=1)
        await _last_written(session, run, an_hour_ago)

        assert not await touch_run(session, run.id)

        stored = await _stored(session, run)
        assert stored.updated_at is not None
        assert make_datetime_utc(stored.updated_at) == an_hour_ago


class TestTheHeartbeat:
    """Write the run on a timer while the sweep runs, and stop it once it is lost."""

    @pytest.fixture
    def touched(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[AsyncMock]:
        """Stand in for the write, on an interval short enough to see several.

        :param monkeypatch: Restores the real interval after the test.
        :return: The stub, answering that the run is still running.
        """
        monkeypatch.setattr(
            service_module, "HEARTBEAT_INTERVAL", timedelta(milliseconds=5)
        )
        stub = AsyncMock(return_value=True)
        with (
            patch.object(service_module, "touch_run", stub),
            patch.object(
                service_module,
                "get_async_session_maker",
                return_value=lambda: nullcontext(MagicMock()),
            ),
        ):
            yield stub

    @pytest.mark.asyncio
    async def test_it_beats_until_the_block_ends(self, touched: AsyncMock) -> None:
        """Write again every interval, and never once the block is left.

        :param touched: The write.
        """
        run_id = ProbeRun().id
        repeated = asyncio.Event()

        def write(*_args: object) -> bool:
            if touched.await_count >= BEATS:
                repeated.set()
            return True

        touched.side_effect = write

        async with service_module._heartbeat(run_id):
            await asyncio.wait_for(repeated.wait(), timeout=5)
        beats = touched.await_count
        await asyncio.sleep(0.05)

        assert touched.await_count == beats
        assert {call.args[1] for call in touched.await_args_list} == {run_id}

    @pytest.mark.asyncio
    async def test_a_failed_write_does_not_stop_it(self, touched: AsyncMock) -> None:
        """Log a write that fails and make the next one anyway.

        :param touched: The write.
        """
        retried = asyncio.Event()

        def write(*_args: object) -> bool:
            if touched.await_count == 1:
                raise OSError("connection refused")
            retried.set()
            return True

        touched.side_effect = write

        async with service_module._heartbeat(ProbeRun().id):
            await asyncio.wait_for(retried.wait(), timeout=5)

    @pytest.mark.asyncio
    async def test_a_lost_run_stops_the_block(self, touched: AsyncMock) -> None:
        """Cancel the block and raise ``RunLostError`` once the run is not running.

        :param touched: The write.
        """
        run_id = ProbeRun().id
        touched.side_effect = [True, False]

        with pytest.raises(RunLostError) as raised:
            async with service_module._heartbeat(run_id):
                await asyncio.sleep(FOREVER)

        assert raised.value.run_id == run_id

    @pytest.mark.asyncio
    async def test_another_cancellation_is_kept(self, touched: AsyncMock) -> None:
        """Let a cancellation that is not the heartbeat's own reach the caller.

        :param touched: The write.
        """
        started = asyncio.Event()

        async def sweep() -> None:
            async with service_module._heartbeat(ProbeRun().id):
                started.set()
                await asyncio.sleep(FOREVER)

        task = asyncio.create_task(sweep())
        await asyncio.wait_for(started.wait(), timeout=5)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task


class TestOneClock:
    """Write ``updated_at`` from the clock the lease is read against."""

    @pytest.mark.asyncio
    async def test_a_progress_write_uses_this_process_clock(
        self, session: AsyncSession
    ) -> None:
        """Stamp the progress write with ``utc_now()``, not the database's ``now()``.

        A database clock behind this process's would make each progress write look
        older than it is, and reap a live sweep between two heartbeats.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(session, ProbeRun())
        then = datetime(2020, 1, 1, tzinfo=UTC)

        with (
            patch.object(
                service_module,
                "get_async_session_maker",
                return_value=lambda: nullcontext(session),
            ),
            patch.object(service_module, "utc_now", return_value=then),
        ):
            await RunProgress(run.id).started([])

        stored = await _stored(session, run)
        assert stored.updated_at is not None
        assert make_datetime_utc(stored.updated_at) == then


class TestFinaliseAfterTheLease:
    """Record a run the lease failed, but whose sweep finished after all, as finished."""

    @pytest.mark.asyncio
    async def test_the_interrupted_detail_is_cleared(
        self, session: AsyncSession
    ) -> None:
        """Write the real outcome and drop the lease's error with it.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(
            session, ProbeRun(status=ProbeRunStatus.FAILED, error=INTERRUPTED_DETAIL)
        )

        await finalise(session, run.id, CLEAN_OUTCOME)

        stored = await _stored(session, run)
        assert (stored.status, stored.error) == (ProbeRunStatus.SUCCESS, None)


class TestFailRunningRun:
    """Fail a run only while it is still running."""

    @pytest.mark.asyncio
    async def test_a_running_run_is_failed(self, session: AsyncSession) -> None:
        """Record the failure on a run still in flight.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(session, ProbeRun())

        await fail_running_run(session, run.id, "connection refused")

        stored = await _stored(session, run)
        assert (stored.status, stored.error) == (
            ProbeRunStatus.FAILED,
            "connection refused",
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "run_status",
        [ProbeRunStatus.SUCCESS, ProbeRunStatus.PARTIAL, ProbeRunStatus.FAILED],
    )
    async def test_a_finished_run_is_not_rewritten(
        self, session: AsyncSession, run_status: ProbeRunStatus
    ) -> None:
        """Leave a run that already reached a terminal status as it is.

        :param session: The database session.
        :param run_status: Its terminal status.
        """
        run = await ProbeRunManager.save(
            session, ProbeRun(status=run_status, error="its own")
        )

        await fail_running_run(session, run.id, "late")

        stored = await _stored(session, run)
        assert (stored.status, stored.error) == (run_status, "its own")
