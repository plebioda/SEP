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

"""add pom discovery run nodes

Revision ID: b7e2d4a90c31
Revises: a3f1c8d24b71
Create Date: 2026-08-12 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "b7e2d4a90c31"
down_revision: Union[str, None] = "a3f1c8d24b71"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {
        column["name"] for column in sa.inspect(bind).get_columns("pom_discovery_run")
    }

    # Same guard the create migration uses: this app's table has been created by
    # metadata in environments that predate its migrations, so a blind ALTER would
    # fail on exactly the databases the migration exists to catch up.
    if "nodes" in columns:
        return

    op.add_column(
        "pom_discovery_run",
        sa.Column(
            "nodes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )


def downgrade() -> None:
    op.drop_column("pom_discovery_run", "nodes")
