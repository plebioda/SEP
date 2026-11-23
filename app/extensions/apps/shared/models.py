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

"""Define the shared Operations run and its dispatch receipts.

Two tables every OM operation shares, both in the ``om`` schema: ``om_run``, the
run pmm-managed's driver creates and keeps the highest leader epoch it has seen
on, keyed by the driver's operation id; and ``om_dispatch_receipt``, one receipt
per dispatch keyed by pmm-managed's ``om_operation_steps.idempotency_key``. The
receipt holds the executor transport facts and a typed redacted result and no
status: the authoritative run and step status live in pmm-managed.

Alembic loads this module through ``spec_from_file_location`` without running the
package ``__init__``, so it imports no sibling OM module. The symbolic schema is
spelled literally here rather than imported from
:mod:`~app.extensions.apps.shared.om.config` for the same reason, the trade
``om_bootstrap``'s own ``models.py`` makes.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, Column, ForeignKey, JSON, Text, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlmodel import Field as SQLField

from app.core.db.models import BaseSQLModel, BaseUUIDSQLModel, DateTimeWithTimezone
from app.core.utils.fields import UTCDatetime

__all__ = ["OM_SCHEMA_SYMBOL", "OmDispatchReceipt", "OmRun"]

#: The symbolic schema OM's tables declare, translated per bind to a real name or
#: to the bind's default schema. Spelled literally, never imported: Alembic loads
#: this module without the package ``__init__``, matching
#: ``app/extensions/apps/shared/om/config.py``'s ``OM_SCHEMA_SYMBOL``.
OM_SCHEMA_SYMBOL = "om_schema"


class OmRun(BaseUUIDSQLModel, table=True):
    """Record one shared Operations run, keyed by the driver's operation id.

    Created empty by pmm-managed's driver, which appends dispatches tick by tick;
    ``id`` is supplied at construction as the driver's ``om_operations.id``, not
    generated here. The row keeps the highest leader ``epoch`` it has seen, which
    the dispatch function advances only after a dispatch is accepted.

    :param kind: The operation kind pmm-managed negotiated for this run, opaque
        to Extensions.
    :param catalogue_version: The step-catalogue version pinned once at create; a
        later change is refused by a trigger.
    :param epoch: The highest leader epoch seen; it never decreases.
    """

    __tablename__ = "om_run"
    __table_args__ = {"schema": OM_SCHEMA_SYMBOL}

    kind: str = SQLField(sa_type=Text)
    catalogue_version: int = SQLField(default=0, sa_type=BigInteger)
    epoch: int = SQLField(default=0, sa_type=BigInteger)


class OmDispatchReceipt(BaseSQLModel, table=True):
    """Record one dispatch's transport receipt, keyed by its idempotency key.

    The ``idempotency_key`` is the dispatch's natural identity, unique and the
    conflict target the dispatch function dedupes on; the inherited integer
    ``id`` is a surrogate primary key the convention requires. The identity
    fields and, once written, the transport facts are immutable, enforced by a
    trigger. The receipt carries no status.

    :param idempotency_key: The dispatch identity, pmm-managed's
        ``om_operation_steps.idempotency_key``.
    :param run_id: The run this dispatch belongs to.
    :param epoch: The leader epoch the dispatch was recorded at.
    :param executor_token: The token the executor dedupes on, one per key.
    :param descriptor_fingerprint: The non-secret descriptor hash a repeated key
        must match; never secret bytes.
    :param node_id: The PMM node this dispatch targets, bound at record time.
    :param accepted_at: When the executor accepted the submission, or ``None``.
    :param submission_id: The executor's submission id, or ``None``.
    :param submitted_at: When the job was submitted, or ``None``.
    :param completed_at: When the job reached a terminal transport state, or
        ``None``.
    :param cancelled_at: A tombstone suppressing a late submit after a cancel, or
        ``None``.
    :param task_history_id: The Tasks history id backing the job, written once
        after acceptance, or ``None``.
    :param result: The typed, bounded, redacted result, or ``None``; never raw
        stdout, stderr or an executor error string.
    """

    __tablename__ = "om_dispatch_receipt"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_om_dispatch_receipt_key"),
        UniqueConstraint("executor_token", name="uq_om_dispatch_receipt_token"),
        {"schema": OM_SCHEMA_SYMBOL},
    )

    idempotency_key: str = SQLField(sa_type=Text, index=True)
    run_id: UUID = SQLField(
        sa_column=Column(
            ForeignKey(f"{OM_SCHEMA_SYMBOL}.om_run.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
    )
    epoch: int = SQLField(sa_type=BigInteger)
    executor_token: str = SQLField(sa_type=Text)
    descriptor_fingerprint: str = SQLField(sa_type=Text)
    node_id: str = SQLField(sa_type=Text)
    accepted_at: UTCDatetime | None = SQLField(
        default=None, sa_type=DateTimeWithTimezone
    )
    submission_id: str | None = SQLField(default=None, sa_type=Text)
    submitted_at: UTCDatetime | None = SQLField(
        default=None, sa_type=DateTimeWithTimezone
    )
    completed_at: UTCDatetime | None = SQLField(
        default=None, sa_type=DateTimeWithTimezone
    )
    cancelled_at: UTCDatetime | None = SQLField(
        default=None, sa_type=DateTimeWithTimezone
    )
    task_history_id: str | None = SQLField(default=None, sa_type=Text)
    result: dict[str, Any] | None = SQLField(
        default=None,
        sa_column=Column(
            JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=True,
        ),
    )
