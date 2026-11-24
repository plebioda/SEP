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

"""Test the backup_mongo writer-hold client, wrapper, and service resolution."""

import asyncio
import logging
from datetime import datetime, timedelta, UTC
from unittest.mock import AsyncMock

import pytest
from aioresponses import aioresponses
from pytest_mock import MockerFixture
from yarl import URL

from app.extensions.apps.backup_mongo.writer_hold import (
    backup_writer_hold,
    pmm_service_ids_for_backup,
    writer_hold,
    WriterHoldConflictError,
    WriterHoldState,
)
from app.extensions.clients.pmm import (
    AcquireWriterHoldResult,
    PMMRemoteAPI,
    WriterHoldConflict,
)
from tests.app.factories import CreatedServiceFactory

pytestmark = pytest.mark.asyncio

_MIN_BEATS = 2
_ACQUIRE_URL = "http://localhost/v1/om/writerHolds:acquire"
_HEARTBEAT_URL = "http://localhost/v1/om/writerHolds:heartbeat"
_RELEASE_URL = "http://localhost/v1/om/writerHolds:release"
_DEADLINE = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.fixture
def pmm_api_client() -> PMMRemoteAPI:
    """Return a PMMRemoteAPI pointed at a local endpoint for aioresponses."""
    return PMMRemoteAPI(endpoint="http://localhost", api_key="test-key")


@pytest.fixture
def mock_pmm() -> AsyncMock:
    """Return a PMMRemoteAPI mock for the hold-wrapper tests."""
    return AsyncMock(spec=PMMRemoteAPI)


async def test_acquire_sends_contract_and_parses_held(
    pmm_api_client: PMMRemoteAPI,
) -> None:
    """Acquire posts the job, services and deadline, and reports the hold taken."""
    with aioresponses() as mock:
        mock.post(_ACQUIRE_URL, payload={"acquired": True})
        async with pmm_api_client as client:
            result = await client.acquire_writer_hold(
                "job-1", ["svc-a", "svc-b"], _DEADLINE
            )
        request = mock.requests[("POST", URL(_ACQUIRE_URL))][0]
    assert result == AcquireWriterHoldResult(acquired=True)
    assert request.kwargs["json"] == {
        "job_id": "job-1",
        "service_ids": ["svc-a", "svc-b"],
        "deadline": "2026-01-02T03:04:05Z",
    }


async def test_acquire_surfaces_conflict(pmm_api_client: PMMRemoteAPI) -> None:
    """Acquire returns the Operations holder when it loses a conflict."""
    with aioresponses() as mock:
        mock.post(
            _ACQUIRE_URL,
            payload={
                "acquired": False,
                "conflict": {
                    "holder_operation_id": "op-9",
                    "holder_mode": "exclusive",
                    "requested_mode": "exclusive",
                },
            },
        )
        async with pmm_api_client as client:
            result = await client.acquire_writer_hold("job-1", ["svc-a"], _DEADLINE)
    assert result.acquired is False
    assert result.conflict == WriterHoldConflict(
        holder_operation_id="op-9",
        holder_mode="exclusive",
        requested_mode="exclusive",
    )


async def test_acquire_reports_no_managed_member(
    pmm_api_client: PMMRemoteAPI,
) -> None:
    """Acquire reports nothing locked and no conflict when no service is managed."""
    with aioresponses() as mock:
        mock.post(_ACQUIRE_URL, payload={"acquired": False})
        async with pmm_api_client as client:
            result = await client.acquire_writer_hold("job-1", ["svc-a"], _DEADLINE)
    assert result.acquired is False
    assert result.conflict is None


async def test_heartbeat_sends_job_and_deadline(
    pmm_api_client: PMMRemoteAPI,
) -> None:
    """Heartbeat posts the job id and the new deadline."""
    with aioresponses() as mock:
        mock.post(_HEARTBEAT_URL, payload={})
        async with pmm_api_client as client:
            await client.heartbeat_writer_hold("job-1", _DEADLINE)
        request = mock.requests[("POST", URL(_HEARTBEAT_URL))][0]
    assert request.kwargs["json"] == {
        "job_id": "job-1",
        "deadline": "2026-01-02T03:04:05Z",
    }


async def test_release_sends_job(pmm_api_client: PMMRemoteAPI) -> None:
    """Release posts only the job id."""
    with aioresponses() as mock:
        mock.post(_RELEASE_URL, payload={})
        async with pmm_api_client as client:
            await client.release_writer_hold("job-1")
        request = mock.requests[("POST", URL(_RELEASE_URL))][0]
    assert request.kwargs["json"] == {"job_id": "job-1"}


async def test_writer_hold_releases_after_success(mock_pmm: AsyncMock) -> None:
    """Hold yields held and releases once when the body completes."""
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(acquired=True)
    async with writer_hold(mock_pmm, job_id="job-1", service_ids=["svc-a"]) as state:
        assert state == WriterHoldState(held=True)
    mock_pmm.release_writer_hold.assert_awaited_once_with("job-1")


async def test_writer_hold_refuses_on_conflict(mock_pmm: AsyncMock) -> None:
    """Hold raises before the body and never releases when Operations holds the lock."""
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(
        acquired=False,
        conflict=WriterHoldConflict(
            holder_operation_id="op-9",
            holder_mode="exclusive",
            requested_mode="exclusive",
        ),
    )
    with pytest.raises(WriterHoldConflictError) as exc:
        async with writer_hold(mock_pmm, job_id="job-1", service_ids=["svc-a"]):
            pytest.fail("body must not run on a conflict")
    assert exc.value.conflict.holder_operation_id == "op-9"
    mock_pmm.release_writer_hold.assert_not_awaited()


async def test_writer_hold_unheld_when_no_managed_member(
    mock_pmm: AsyncMock,
) -> None:
    """Hold yields unheld and neither heartbeats nor releases when nothing is locked."""
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(acquired=False)
    async with writer_hold(mock_pmm, job_id="job-1", service_ids=["svc-a"]) as state:
        assert state == WriterHoldState(held=False)
    mock_pmm.heartbeat_writer_hold.assert_not_awaited()
    mock_pmm.release_writer_hold.assert_not_awaited()


async def test_writer_hold_releases_on_exception(mock_pmm: AsyncMock) -> None:
    """Hold releases when the body raises."""
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(acquired=True)
    with pytest.raises(RuntimeError, match="boom"):
        async with writer_hold(mock_pmm, job_id="job-1", service_ids=["svc-a"]):
            raise RuntimeError("boom")
    mock_pmm.release_writer_hold.assert_awaited_once_with("job-1")


async def test_writer_hold_heartbeats_while_held(mock_pmm: AsyncMock) -> None:
    """Hold heartbeats repeatedly while the body runs."""
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(acquired=True)
    two_beats = asyncio.Event()

    async def _count(_job_id: str, _deadline: datetime) -> None:
        if mock_pmm.heartbeat_writer_hold.await_count >= _MIN_BEATS:
            two_beats.set()

    mock_pmm.heartbeat_writer_hold.side_effect = _count
    async with writer_hold(
        mock_pmm,
        job_id="job-1",
        service_ids=["svc-a"],
        lease=timedelta(minutes=1),
        heartbeat_interval=timedelta(seconds=0.01),
    ):
        await asyncio.wait_for(two_beats.wait(), timeout=2)
    assert mock_pmm.heartbeat_writer_hold.await_count >= _MIN_BEATS


async def test_writer_hold_swallows_release_failure(
    mock_pmm: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    """A failed release is logged, not raised, so the body's outcome stands."""
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(acquired=True)
    mock_pmm.release_writer_hold.side_effect = RuntimeError("network down")
    with caplog.at_level(logging.WARNING):
        async with writer_hold(mock_pmm, job_id="job-1", service_ids=["svc-a"]):
            pass
    mock_pmm.release_writer_hold.assert_awaited_once_with("job-1")
    assert "Failed to release writer hold for backup job job-1" in caplog.text


async def test_pmm_service_ids_for_backup_returns_external_id(
    mocker: MockerFixture,
) -> None:
    """Resolution maps a local MongoDB service to its PMM service id."""
    service = CreatedServiceFactory.build()
    mocker.patch(
        "app.extensions.apps.backup_mongo.writer_hold.get_created_entity",
        new=AsyncMock(return_value=service),
    )
    result = await pmm_service_ids_for_backup(AsyncMock(), service.id)
    assert result == [service.external_id]


async def test_backup_writer_hold_resolves_then_holds(
    mock_pmm: AsyncMock, mocker: MockerFixture
) -> None:
    """The seam resolves the service id, then acquires and releases the hold."""
    service = CreatedServiceFactory.build()
    mocker.patch(
        "app.extensions.apps.backup_mongo.writer_hold.get_created_entity",
        new=AsyncMock(return_value=service),
    )
    mock_pmm.acquire_writer_hold.return_value = AcquireWriterHoldResult(acquired=True)
    async with backup_writer_hold(
        mock_pmm, AsyncMock(), job_id="job-1", service_id=service.id
    ) as state:
        assert state == WriterHoldState(held=True)
    acquire_args = mock_pmm.acquire_writer_hold.await_args.args
    assert acquire_args[0] == "job-1"
    assert acquire_args[1] == [service.external_id]
    mock_pmm.release_writer_hold.assert_awaited_once_with("job-1")
