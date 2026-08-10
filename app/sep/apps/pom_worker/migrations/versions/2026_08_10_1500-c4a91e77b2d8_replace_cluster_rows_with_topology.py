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

"""replace per-cluster rows with one topology document

POM now assembles a single ``environments -> clusters -> services`` document per run
instead of one status document per cluster, so ``pom_cluster`` goes and
``pom_snapshot`` takes its place. ``pom_node`` gains ``external_id``, PMM's service
UUID, which the document publishes as ``service_id``.

Existing rows are **deleted rather than migrated**. Every ``pom_cluster`` document is
in the old shape with no path to the new one -- different grouping, different field
names, no ``status`` or load figures anywhere in it -- and the runs that produced them
would otherwise survive as history the API cannot render. Re-running discovery rebuilds
everything from VictoriaMetrics in seconds, so there is nothing here worth converting.

Revision ID: c4a91e77b2d8
Revises: b7d31f0a5c92
Create Date: 2026-08-10 15:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c4a91e77b2d8"
down_revision: Union[str, None] = "b7d31f0a5c92"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    """Return the existing table names.

    :return: The table names.
    """
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    """Return the existing column names of ``table``.

    :param table: The table to inspect.
    :return: Its column names.
    """
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    tables = _tables()

    if "pom_cluster" in tables:
        op.drop_table("pom_cluster")

    # Snapshots are rebuilt on the next run, and a run with no snapshot is a run the
    # API cannot serve. Clear both tables so history starts clean rather than carrying
    # rows that render as nothing. Order matters: pom_node references pom_run.
    if "pom_node" in tables:
        op.execute("DELETE FROM pom_node")
    if "pom_run" in tables:
        op.execute("DELETE FROM pom_run")

    if "pom_node" in tables and "external_id" not in _columns("pom_node"):
        op.add_column(
            "pom_node", sa.Column("external_id", sa.String(), nullable=True)
        )
        op.create_index(
            op.f("ix_pom_node_external_id"), "pom_node", ["external_id"], unique=False
        )

    if "pom_snapshot" not in tables:
        op.create_table(
            "pom_snapshot",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            # BaseSQLModel contributes both timestamps to every table it backs.
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("run_id", sa.Uuid(), nullable=False),
            sa.Column(
                "document", postgresql.JSONB(none_as_null=True), nullable=False
            ),
            sa.ForeignKeyConstraint(["run_id"], ["pom_run.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_pom_snapshot_run_id"), "pom_snapshot", ["run_id"], unique=True
        )


def downgrade() -> None:
    tables = _tables()

    if "pom_snapshot" in tables:
        op.drop_table("pom_snapshot")

    if "pom_node" in tables and "external_id" in _columns("pom_node"):
        op.drop_index(op.f("ix_pom_node_external_id"), table_name="pom_node")
        op.drop_column("pom_node", "external_id")

    if "pom_cluster" not in tables:
        op.create_table(
            "pom_cluster",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("run_id", sa.Uuid(), nullable=False),
            sa.Column("cluster_id", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("cluster_type", sa.String(), nullable=False),
            sa.Column("environment", sa.String(), nullable=True),
            sa.Column("health_status", sa.String(), nullable=False),
            sa.Column("members_total", sa.Integer(), nullable=False),
            sa.Column("members_observed", sa.Integer(), nullable=False),
            sa.Column(
                "document", postgresql.JSONB(none_as_null=True), nullable=False
            ),
            sa.ForeignKeyConstraint(["run_id"], ["pom_run.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
