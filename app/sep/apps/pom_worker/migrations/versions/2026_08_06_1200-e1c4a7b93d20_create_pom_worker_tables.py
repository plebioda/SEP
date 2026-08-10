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

"""create pom worker tables

Revision ID: e1c4a7b93d20
Revises:
Create Date: 2026-08-06 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = "e1c4a7b93d20"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = ("pom_worker",)
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    existing_tables = sa.inspect(bind).get_table_names()

    if "pom_run" not in existing_tables:
        op.create_table(
            "pom_run",
            sa.Column("id", sa.Uuid(), autoincrement=False, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "status",
                sa.Enum(
                    "RUNNING",
                    "SUCCESS",
                    "PARTIAL",
                    "FAILED",
                    name="pomrunstatus",
                    native_enum=False,
                    create_constraint=True,
                ),
                nullable=False,
            ),
            sa.Column("services_total", sa.Integer(), nullable=False),
            sa.Column("services_resolved", sa.Integer(), nullable=False),
            sa.Column("services_orphaned", sa.Integer(), nullable=False),
            sa.Column("probes_ok", sa.Integer(), nullable=False),
            sa.Column("error", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_pom_run_started_at"),
            "pom_run",
            ["started_at"],
            unique=False,
        )
        op.create_index(
            op.f("ix_pom_run_status"), "pom_run", ["status"], unique=False
        )

    if "pom_node" not in existing_tables:
        op.create_table(
            "pom_node",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("run_id", sa.Uuid(), nullable=False),
            sa.Column(
                "service_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False
            ),
            sa.Column("service_id", sa.Integer(), nullable=True),
            sa.Column("cluster", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
            sa.Column(
                "replication_set", sqlmodel.sql.sqltypes.AutoString(), nullable=True
            ),
            sa.Column(
                "environment", sqlmodel.sql.sqltypes.AutoString(), nullable=True
            ),
            sa.Column("node_name", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
            sa.Column(
                "node_address", sqlmodel.sql.sqltypes.AutoString(), nullable=True
            ),
            sa.Column("port", sa.Integer(), nullable=True),
            sa.Column(
                "executor_host", sqlmodel.sql.sqltypes.AutoString(), nullable=True
            ),
            sa.Column(
                "resolution",
                sa.Enum(
                    "NAME",
                    "ADDRESS",
                    "ORPHANED",
                    name="noderesolution",
                    native_enum=False,
                    create_constraint=True,
                ),
                nullable=False,
            ),
            sa.Column(
                "probe_status",
                sa.Enum(
                    "OK",
                    "FAILED",
                    "SKIPPED",
                    name="probestatus",
                    native_enum=False,
                    create_constraint=True,
                ),
                nullable=False,
            ),
            # The dispatched run-python run that carried this service's probe, so a
            # failure traces into the Tasks API and Nomad without re-deriving which
            # dispatch covered which service.
            sa.Column("task_history_id", sa.Integer(), nullable=True),
            # Must be JSONB, not JSON: the model types this with AutoJSON, which
            # resolves to JSONB on PostgreSQL, and a plain JSON column here reads
            # back as schema drift. The full probe record lives in this column
            # because VictoriaMetrics caps a label value at 4096 bytes.
            sa.Column(
                "probe",
                postgresql.JSONB(astext_type=sa.Text()).with_variant(
                    sa.JSON(), "sqlite"
                ),
                nullable=True,
            ),
            sa.Column("error", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
            sa.ForeignKeyConstraint(["run_id"], ["pom_run.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for column in (
            "run_id",
            "service_name",
            "cluster",
            "replication_set",
            "environment",
            "executor_host",
            "resolution",
            "probe_status",
            "task_history_id",
        ):
            op.create_index(
                op.f(f"ix_pom_node_{column}"),
                "pom_node",
                [column],
                unique=False,
            )
        op.create_index(
            "ix_pom_node_run_service",
            "pom_node",
            ["run_id", "service_name"],
            unique=False,
        )

    if "pom_cluster" not in existing_tables:
        op.create_table(
            "pom_cluster",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("run_id", sa.Uuid(), nullable=False),
            sa.Column("cluster_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
            sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
            sa.Column(
                "cluster_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False
            ),
            sa.Column(
                "environment", sqlmodel.sql.sqltypes.AutoString(), nullable=True
            ),
            sa.Column(
                "health_status", sqlmodel.sql.sqltypes.AutoString(), nullable=False
            ),
            sa.Column("members_total", sa.Integer(), nullable=False),
            sa.Column("members_observed", sa.Integer(), nullable=False),
            # The assembled status document the API serves. JSONB so a future
            # containment or path query does not need a table rewrite.
            sa.Column(
                "document",
                postgresql.JSONB(astext_type=sa.Text()).with_variant(
                    sa.JSON(), "sqlite"
                ),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["run_id"], ["pom_run.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for column in (
            "run_id",
            "cluster_id",
            "name",
            "cluster_type",
            "environment",
            "health_status",
        ):
            op.create_index(
                op.f(f"ix_pom_cluster_{column}"),
                "pom_cluster",
                [column],
                unique=False,
            )
        op.create_index(
            "ix_pom_cluster_run_cluster",
            "pom_cluster",
            ["run_id", "cluster_id"],
            unique=False,
        )


def downgrade() -> None:
    # Mirrors upgrade()'s existence checks: this revision is edited in place while
    # the schema is still disposable, so a downgrade can legitimately meet a
    # database that predates one of the tables.
    bind = op.get_bind()
    existing_tables = set(sa.inspect(bind).get_table_names())
    for table in ("pom_cluster", "pom_node", "pom_run"):
        if table in existing_tables:
            op.drop_table(table)
