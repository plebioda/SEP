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

A live sweep writes its run every ``HEARTBEAT_INTERVAL``. A running run that goes
``RUN_LEASE`` without a write lost its sweep, to a worker restart or kill, or to a
PMM Server restart that took the database its failure would have been written to,
and the next scan fails it.
"""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, nullcontext
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from kombu.exceptions import OperationalError as KombuOperationalError
from sqlmodel import col
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status

from app.core.utils.date_time import make_datetime_utc, utc_now
from app.extensions.apps.om_inventory import celery as celery_module
from app.extensions.apps.om_inventory import service as service_module
from app.extensions.apps.om_inventory.api_routes import QUEUE_UNAVAILABLE_DETAIL
from app.extensions.apps.om_inventory.config import om_inventory_settings
from app.extensions.apps.om_inventory.crud import (
    conflicting_run,
    fail_running_run,
    INTERRUPTED_DETAIL,
    ProbeRunManager,
    RUN_LEASE,
    touch_run,
)
from app.extensions.apps.om_inventory.models import ProbeRun, ProbeRunStatus
from app.extensions.apps.om_inventory.service import run_probe
from tests.app.extensions.apps.om_inventory.conftest import BASE, CLEAN_OUTCOME

#: Far longer than any run in these tests, so only the lease can reap one.
STALE_AFTER = timedelta(hours=4)
#: Writes to wait for, so a test sees the timer repeat and not only the first one.
BEATS = 3


@pytest.fixture
def enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn the sweep on, since ``run_probe`` refuses to run while it is off.

    :param monkeypatch: Restores the real value after the test.
    """
    monkeypatch.setattr(om_inventory_settings, "ENABLED", True)


@pytest.fixture
def service_session(session: AsyncSession) -> Iterator[AsyncSession]:
    """Hand the test session to every session the sweep functions open.

    :param session: The test session.
    :return: The same session, while the patch is in place.
    """
    with patch.object(
        service_module,
        "get_async_session_maker",
        return_value=lambda: nullcontext(session),
    ):
        yield session


async def _last_written(session: AsyncSession, run: ProbeRun, when: datetime) -> None:
    """Make ``when`` the run's last write, as a sweep that stopped then would leave it.

    :param session: The database session.
    :param run: The run.
    :param when: Its last write.
    """
    await ProbeRunManager.update_where(
        session, {"updated_at": when}, col(ProbeRun.id) == run.id
    )


async def _assert_reaped_by_the_lease(session: AsyncSession) -> None:
    """Assert a running run silent for longer than the lease is failed, not honoured.

    :param session: The database session.
    """
    run = await ProbeRunManager.save(session, ProbeRun())
    await _last_written(session, run, utc_now() - RUN_LEASE - timedelta(seconds=1))

    assert await conflicting_run(session, None, stale_after=STALE_AFTER) is None

    stored = await ProbeRunManager.get(session, id=run.id)
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
        """Do the same with PostgreSQL's own timestamps.

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
            pytest.param(RUN_LEASE + timedelta(seconds=1), True, id="past-the-lease"),
            pytest.param(timedelta(seconds=1), False, id="just-queued"),
        ],
    )
    async def test_a_run_never_written_counts_from_its_creation(
        self, session: AsyncSession, waited: timedelta, *, reaped: bool
    ) -> None:
        """Judge a run still waiting for its worker by when it was created.

        :param session: The database session.
        :param waited: How long ago it was created.
        :param reaped: Whether it is expected failed.
        """
        run = await ProbeRunManager.save(
            session, ProbeRun(created_at=utc_now() - waited)
        )

        blocking = await conflicting_run(session, None, stale_after=STALE_AFTER)

        assert (blocking is None) is reaped
        stored = await ProbeRunManager.get(session, id=run.id)
        assert (stored.status is ProbeRunStatus.FAILED) is reaped


class TestTouchRun:
    """Mark a run alive only while it is still running."""

    @pytest.mark.asyncio
    async def test_a_running_run_is_marked_alive(self, session: AsyncSession) -> None:
        """Move the run's last write to now.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(session, ProbeRun())
        await _last_written(session, run, utc_now() - timedelta(hours=1))

        await touch_run(session, run.id)

        stored = await ProbeRunManager.get(session, id=run.id)
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

        await touch_run(session, run.id)

        stored = await ProbeRunManager.get(session, id=run.id)
        assert stored.updated_at is not None
        assert make_datetime_utc(stored.updated_at) == an_hour_ago


class TestTheHeartbeat:
    """Write the run on a timer for as long as the sweep runs, and not after."""

    @pytest.fixture
    def touched(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[AsyncMock]:
        """Stand in for the write, on an interval short enough to see several.

        :param monkeypatch: Restores the real interval after the test.
        :return: The stub, while the patches are in place.
        """
        monkeypatch.setattr(
            service_module, "HEARTBEAT_INTERVAL", timedelta(milliseconds=5)
        )
        stub = AsyncMock()
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

        def write(*_args: object) -> None:
            if touched.await_count >= BEATS:
                repeated.set()

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

        def write(*_args: object) -> None:
            if touched.await_count == 1:
                raise OSError("connection refused")
            retried.set()

        touched.side_effect = write

        async with service_module._heartbeat(ProbeRun().id):
            await asyncio.wait_for(retried.wait(), timeout=5)


@pytest.mark.usefixtures("enabled")
class TestRunProbe:
    """Sweep under a heartbeat, and never for a run that is no longer waiting."""

    @pytest.mark.asyncio
    async def test_the_sweep_runs_inside_the_heartbeat(
        self, service_session: AsyncSession
    ) -> None:
        """Keep the run alive across the sweep, the estate write and the finalise.

        :param service_session: The session every sweep function opens.
        """
        run = await ProbeRunManager.save(service_session, ProbeRun())
        beating: list[bool] = [False]
        seen: list[bool] = []

        @asynccontextmanager
        async def heartbeat(_run_id: object) -> AsyncIterator[None]:
            beating[0] = True
            yield
            beating[0] = False

        async def record(*_args: object, **_kwargs: object) -> object:
            seen.append(beating[0])
            return CLEAN_OUTCOME

        with (
            patch.object(service_module, "_heartbeat", heartbeat),
            patch.object(service_module, "sweep", AsyncMock(side_effect=record)),
            patch.object(
                service_module, "persist_estate", AsyncMock(side_effect=record)
            ),
            patch.object(service_module, "finalise", AsyncMock(side_effect=record)),
        ):
            await run_probe(execution_id=run.id, node_ids=[])

        assert seen == [True, True, True]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("run_status", "error"),
        [
            pytest.param(ProbeRunStatus.FAILED, INTERRUPTED_DETAIL, id="reaped"),
            pytest.param(ProbeRunStatus.SUCCESS, None, id="finished"),
        ],
    )
    async def test_a_run_no_longer_running_is_not_swept(
        self,
        service_session: AsyncSession,
        run_status: ProbeRunStatus,
        error: str | None,
    ) -> None:
        """Leave a run its message reached too late as it is, and sweep nothing.

        The lease fails a run whose message waited longer than it, as one does while
        the worker is down. Sweeping it then would overwrite that failure, after a
        newer scan was already let through on the strength of it.

        :param service_session: The session every sweep function opens.
        :param run_status: The run's status when its message arrives.
        :param error: Its failure detail.
        """
        run = await ProbeRunManager.save(
            service_session, ProbeRun(status=run_status, error=error)
        )
        sweep = AsyncMock(return_value=CLEAN_OUTCOME)

        with patch.object(service_module, "sweep", sweep):
            assert await run_probe(execution_id=run.id, node_ids=[]) == run.id

        sweep.assert_not_awaited()
        stored = await ProbeRunManager.get(service_session, id=run.id)
        assert (stored.status, stored.error) == (run_status, error)


class TestFailRunningRun:
    """Fail a run only while it is still running."""

    @pytest.mark.asyncio
    async def test_a_running_run_is_failed(self, session: AsyncSession) -> None:
        """Record the failure on a run still in flight.

        :param session: The database session.
        """
        run = await ProbeRunManager.save(session, ProbeRun())

        assert await fail_running_run(session, run.id, "connection refused")

        stored = await ProbeRunManager.get(session, id=run.id)
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

        assert not await fail_running_run(session, run.id, "late")

        stored = await ProbeRunManager.get(session, id=run.id)
        assert (stored.status, stored.error) == (run_status, "its own")


class TestTriggerThatCannotQueue:
    """Fail the run, rather than leave it running, when its task cannot be queued."""

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("enabled")
    async def test_answers_503_and_fails_the_run(
        self, api: AsyncClient, session: AsyncSession
    ) -> None:
        """Answer 503 and record why on the run.

        :param api: The authenticated client.
        :param session: The database session.
        """
        with patch.object(
            celery_module.run_om_probe,
            "delay",
            side_effect=KombuOperationalError("Connection refused"),
        ):
            response = await api.post(f"{BASE}/runs")

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        runs = await ProbeRunManager.list(session)
        assert [(run.status, run.error) for run in runs] == [
            (ProbeRunStatus.FAILED, QUEUE_UNAVAILABLE_DETAIL)
        ]
