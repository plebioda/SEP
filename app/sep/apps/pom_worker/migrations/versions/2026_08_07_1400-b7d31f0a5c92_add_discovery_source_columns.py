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

"""add discovery source columns

Adds the columns multi-source discovery needs:

* ``pom_run.origin_node`` -- the PMM node a snapshot was taken from.
* ``pom_run.sources``     -- per-source status and counters, the run's receipt.
* ``pom_node.facts``      -- the merged field mapping, with provenance per field.

All three are ``JSONB`` rather than ``sa.JSON()``: the models type them with an
explicit ``postgresql.JSONB`` variant, and a plain ``sa.JSON()`` here would create a
``json`` column that ``alembic check`` then reports as drift forever after.

Revision ID: b7d31f0a5c92
Revises: e1c4a7b93d20
Create Date: 2026-08-07 14:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7d31f0a5c92"
down_revision: Union[str, None] = "e1c4a7b93d20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> set[str]:
    """Return the existing column names of ``table``.

    :param table: The table to inspect.
    :return: Its column names.
    """
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    run_columns = _columns("pom_run")
    if "origin_node" not in run_columns:
        op.add_column("pom_run", sa.Column("origin_node", sa.String(), nullable=True))
    if "sources" not in run_columns:
        op.add_column(
            "pom_run",
            sa.Column("sources", postgresql.JSONB(none_as_null=True), nullable=True),
        )

    if "facts" not in _columns("pom_node"):
        op.add_column(
            "pom_node",
            sa.Column("facts", postgresql.JSONB(none_as_null=True), nullable=True),
        )


def downgrade() -> None:
    run_columns = _columns("pom_run")
    if "facts" in _columns("pom_node"):
        op.drop_column("pom_node", "facts")
    if "sources" in run_columns:
        op.drop_column("pom_run", "sources")
    if "origin_node" in run_columns:
        op.drop_column("pom_run", "origin_node")
