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

"""Exercise the idempotent dispatch function against real PostgreSQL.

The ``om_record_dispatch`` function is PL/pgSQL, so the crash matrix runs on a
real engine: the migration is applied to the test database, then dispatches are
recorded through it. The cases pin the fencing an at-least-once dispatcher relies
on -- a stale leader epoch is refused with no row written and no epoch advance, a
repeated key returns the stored token and mints nothing new, a drifted descriptor
or a cancelled key is refused, and the run epoch advances only after a dispatch is
accepted.
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.utils.date_time import utc_now
from app.core.utils.fields import AsyncDatabaseEngine
from app.extensions.apps.shared.models import (
    OM_SCHEMA_SYMBOL,
    OmDispatchReceipt,
    OmRun,
)
from app.extensions.apps.shared.om.config import om_schema
from app.extensions.apps.shared.om.dispatch import record_dispatch
from app.extensions.config import extensions_settings
from tests.app.alembic_paths import ALEMBIC_INI

pytestmark = [pytest.mark.postgres, pytest.mark.asyncio]

#: The epoch a run is seeded at, and the next one a later dispatch advances it to.
_START_EPOCH = 5
_NEWER_EPOCH = 6


@pytest_asyncio.fixture
async def dispatch_session(postgres_async_url, monkeypatch):
    """Apply the migration to the test database and yield a session on it.

    Point the Extensions settings at the test PostgreSQL, upgrade the extensions
    track so ``om_record_dispatch`` and the OM tables exist, and yield a session
    whose engine translates the symbolic OM schema the same way the function
    resolution does. Drop and recreate ``public`` on teardown so the next test
    starts clean.

    :param postgres_async_url: The test database's async URL.
    :param monkeypatch: The fixture used to redirect the Extensions database.
    :return: A session bound to the upgraded test database.
    """
    database = extensions_settings.DATABASE
    monkeypatch.setattr(database, "ENGINE", AsyncDatabaseEngine.POSTGRESQL)
    monkeypatch.setattr(database, "USER", postgres_async_url.username)
    monkeypatch.setattr(
        database,
        "PASSWORD",
        SecretStr(postgres_async_url.password) if postgres_async_url.password else None,
    )
    monkeypatch.setattr(database, "HOST", postgres_async_url.host)
    monkeypatch.setattr(database, "PORT", postgres_async_url.port)
    monkeypatch.setattr(database, "NAME", postgres_async_url.database)

    command.upgrade(Config(str(ALEMBIC_INI), ini_section="extensions"), "heads")

    engine = create_async_engine(postgres_async_url).execution_options(
        schema_translate_map={OM_SCHEMA_SYMBOL: om_schema(database)}
    )
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with maker() as session:
            yield session
    finally:
        await engine.dispose()
        sync = create_engine(postgres_async_url.set(drivername="postgresql+psycopg"))
        try:
            with sync.begin() as conn:
                conn.exec_driver_sql("DROP SCHEMA public CASCADE")
                conn.exec_driver_sql("CREATE SCHEMA public")
        finally:
            sync.dispose()


async def _seed_run(session: AsyncSession, *, epoch: int) -> OmRun:
    """Create a run at ``epoch`` and return it.

    :param session: The session to create through.
    :param epoch: The leader epoch the run starts at.
    :return: The created run.
    """
    run = OmRun(id=uuid4(), kind="install", catalogue_version=1, epoch=epoch)
    session.add(run)
    await session.commit()
    return run


async def _receipt_count(session: AsyncSession) -> int:
    """Return how many dispatch receipts exist.

    :param session: The session to count through.
    :return: The receipt row count.
    """
    return (await session.exec(select(func.count()).select_from(OmDispatchReceipt))).one()


async def _run_epoch(session: AsyncSession, run_id) -> int:
    """Return a run's current epoch.

    :param session: The session to read through.
    :param run_id: The run to read.
    :return: The run's epoch.
    """
    return (await session.exec(select(OmRun.epoch).where(OmRun.id == run_id))).one()


async def test_first_dispatch_records_and_returns_the_candidate_token(
    dispatch_session: AsyncSession,
) -> None:
    """Record a first dispatch and hand back the token the caller offered."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    recorded = await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key="op/run/op/run/apply/1",
        epoch=_START_EPOCH,
        executor_token="tok-a",
        descriptor_fingerprint="fp-a",
        node_id="node-1",
    )
    await dispatch_session.commit()
    assert recorded.first_time is True
    assert recorded.executor_token == "tok-a"
    assert await _receipt_count(dispatch_session) == 1


async def test_a_repeat_returns_the_stored_token_and_mints_nothing(
    dispatch_session: AsyncSession,
) -> None:
    """Return the stored token on a repeated key and write no second row."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    key = "op/run/op/run/apply/1"
    await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key=key,
        epoch=_START_EPOCH,
        executor_token="tok-a",
        descriptor_fingerprint="fp-a",
        node_id="node-1",
    )
    await dispatch_session.commit()
    repeat = await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key=key,
        epoch=_START_EPOCH,
        executor_token="tok-b",
        descriptor_fingerprint="fp-a",
        node_id="node-1",
    )
    await dispatch_session.commit()
    assert repeat.first_time is False
    assert repeat.executor_token == "tok-a"
    assert await _receipt_count(dispatch_session) == 1


async def test_a_stale_epoch_is_refused_without_writing_a_row(
    dispatch_session: AsyncSession,
) -> None:
    """Refuse a dispatch below the run epoch and leave the epoch and rows alone."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    with pytest.raises(DBAPIError):
        await record_dispatch(
            dispatch_session,
            run_id=run.id,
            idempotency_key="op/run/op/run/apply/1",
            epoch=_START_EPOCH - 1,
            executor_token="tok-a",
            descriptor_fingerprint="fp-a",
            node_id="node-1",
        )
    await dispatch_session.rollback()
    assert await _receipt_count(dispatch_session) == 0
    assert await _run_epoch(dispatch_session, run.id) == _START_EPOCH


async def test_a_descriptor_mismatch_on_a_repeat_is_refused(
    dispatch_session: AsyncSession,
) -> None:
    """Refuse a repeated key whose descriptor fingerprint drifted."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    key = "op/run/op/run/apply/1"
    await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key=key,
        epoch=_START_EPOCH,
        executor_token="tok-a",
        descriptor_fingerprint="fp-a",
        node_id="node-1",
    )
    await dispatch_session.commit()
    with pytest.raises(DBAPIError):
        await record_dispatch(
            dispatch_session,
            run_id=run.id,
            idempotency_key=key,
            epoch=_START_EPOCH,
            executor_token="tok-a",
            descriptor_fingerprint="fp-drifted",
            node_id="node-1",
        )
    await dispatch_session.rollback()


async def test_a_cancelled_dispatch_is_not_resubmitted(
    dispatch_session: AsyncSession,
) -> None:
    """Refuse a repeat of a dispatch whose tombstone is set."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    key = "op/run/op/run/apply/1"
    await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key=key,
        epoch=_START_EPOCH,
        executor_token="tok-a",
        descriptor_fingerprint="fp-a",
        node_id="node-1",
    )
    await dispatch_session.commit()
    receipt = (
        await dispatch_session.exec(
            select(OmDispatchReceipt).where(OmDispatchReceipt.idempotency_key == key)
        )
    ).one()
    receipt.cancelled_at = utc_now()
    dispatch_session.add(receipt)
    await dispatch_session.commit()
    with pytest.raises(DBAPIError):
        await record_dispatch(
            dispatch_session,
            run_id=run.id,
            idempotency_key=key,
            epoch=_START_EPOCH,
            executor_token="tok-a",
            descriptor_fingerprint="fp-a",
            node_id="node-1",
        )
    await dispatch_session.rollback()


async def test_a_null_token_is_refused(dispatch_session: AsyncSession) -> None:
    """Refuse a dispatch whose dedupe token is null."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    schema = om_schema(extensions_settings.DATABASE)
    generator = func if schema is None else getattr(func, schema)
    call = generator.om_record_dispatch(
        run.id, "op/run/op/run/apply/1", _START_EPOCH, None, "fp-a", "node-1"
    ).table_valued("receipt_key", "first_time", "executor_token")
    with pytest.raises(DBAPIError):
        await dispatch_session.exec(select(call.c.receipt_key))
    await dispatch_session.rollback()


async def test_a_newer_epoch_advances_the_run(dispatch_session: AsyncSession) -> None:
    """Advance the run epoch once a dispatch at a newer epoch is accepted."""
    run = await _seed_run(dispatch_session, epoch=_START_EPOCH)
    await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key="op/run/op/run/apply/1",
        epoch=_START_EPOCH,
        executor_token="tok-a",
        descriptor_fingerprint="fp-a",
        node_id="node-1",
    )
    await record_dispatch(
        dispatch_session,
        run_id=run.id,
        idempotency_key="op/run/op/run/apply/2",
        epoch=_NEWER_EPOCH,
        executor_token="tok-b",
        descriptor_fingerprint="fp-b",
        node_id="node-1",
    )
    await dispatch_session.commit()
    assert await _run_epoch(dispatch_session, run.id) == _NEWER_EPOCH
