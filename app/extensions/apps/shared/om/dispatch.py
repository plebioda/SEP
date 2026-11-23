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

"""Record a dispatch before the executor runs, and fingerprint its descriptor.

The caller commits :func:`record_dispatch` before it calls the executor: the
``om_record_dispatch`` function refuses a stale leader epoch with no row written,
and on a repeated idempotency key returns the stored ``executor_token`` so the
caller re-submits the same token rather than minting a new one. The function is
PL/pgSQL and exists only on a PostgreSQL bind; it is reached by name through the
OM schema, which is why this module resolves that schema rather than relying on
the session's ``schema_translate_map`` (which rewrites ORM table references, not
a function named in raw text).

:func:`descriptor_fingerprint` builds the non-secret descriptor hash a repeated
key must match: the catalogue version, the step's declared privilege and target,
the non-secret parameters, and a secret's ``secret_id`` reference -- never the
secret's bytes.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.extensions.apps.shared.om.config import om_schema
from app.extensions.apps.shared.om.step_contract import StepContract
from app.extensions.config import extensions_settings

__all__ = ["RecordedDispatch", "descriptor_fingerprint", "record_dispatch"]


@dataclass(frozen=True, slots=True)
class RecordedDispatch:
    """Carry what ``om_record_dispatch`` committed for one dispatch.

    :param receipt_key: The dispatch's idempotency key, echoed back.
    :param first_time: Whether this call inserted the receipt rather than finding
        an existing one for the key.
    :param executor_token: The token to submit the executor job under; the stored
        one on a repeat, so the executor dedupes rather than starting a new job.
    """

    receipt_key: str
    first_time: bool
    executor_token: str


def descriptor_fingerprint(
    catalogue_version: int,
    contract: StepContract,
    params: Mapping[str, Any],
    secret_id: str | None,
) -> str:
    """Return the non-secret descriptor hash a repeated dispatch key must match.

    Hash the catalogue version, the step's declared privilege and target, the
    non-secret ``params``, and a secret's ``secret_id`` reference, in a canonical
    form. A secret's bytes never enter it: only the reference does, so a receipt
    carrying the fingerprint leaks nothing even though a mismatch is refused.

    :param catalogue_version: The step-catalogue version pinned on the run.
    :param contract: The step's declared contract.
    :param params: The dispatch's non-secret parameters.
    :param secret_id: The referenced secret's id, or ``None`` when the step needs
        no secret.
    :return: The descriptor fingerprint as a hex SHA-256 digest.
    """
    canonical = json.dumps(
        {
            "catalogue_version": catalogue_version,
            "privilege": contract.privilege.value,
            "target_kind": contract.target_kind.value,
            "params": params,
            "secret_id": secret_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


async def record_dispatch(
    session: AsyncSession,
    *,
    run_id: UUID,
    idempotency_key: str,
    epoch: int,
    executor_token: str,
    descriptor_fingerprint: str,
    node_id: str,
) -> RecordedDispatch:
    """Record a dispatch before the executor runs, and return the stored token.

    Call and commit this before submitting the executor job. The function raises
    on a stale epoch (with no row written), on a repeat whose descriptor or node
    does not match the stored one, and on a repeat of a cancelled dispatch; it
    advances the run epoch only after accepting the dispatch. PL/pgSQL only, so
    this runs on a PostgreSQL bind.

    :param session: The session to record through; the caller commits it.
    :param run_id: The run this dispatch belongs to.
    :param idempotency_key: The dispatch's canonical identity.
    :param epoch: The leader epoch the caller holds.
    :param executor_token: The token candidate, stored only on the first insert
        for the key.
    :param descriptor_fingerprint: The non-secret descriptor hash from
        :func:`descriptor_fingerprint`.
    :param node_id: The PMM node this dispatch targets.
    :return: The committed receipt key, whether it was first-recorded, and the
        token to submit under.
    :raises sqlalchemy.exc.DBAPIError: When the function refuses the dispatch (a
        stale epoch, a descriptor mismatch, a cancelled key, a missing run, or a
        key belonging to another run).
    """
    schema = om_schema(extensions_settings.DATABASE)
    generator = func if schema is None else getattr(func, schema)
    call = generator.om_record_dispatch(
        run_id, idempotency_key, epoch, executor_token, descriptor_fingerprint, node_id
    ).table_valued("receipt_key", "first_time", "executor_token")
    receipt_key, first_time, stored_token = (
        await session.exec(
            select(call.c.receipt_key, call.c.first_time, call.c.executor_token)
        )
    ).one()
    return RecordedDispatch(
        receipt_key=receipt_key, first_time=first_time, executor_token=stored_token
    )
