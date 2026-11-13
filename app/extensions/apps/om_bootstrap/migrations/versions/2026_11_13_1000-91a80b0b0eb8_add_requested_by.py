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
"""add bootstrap_run.requested_by

Revision ID: 91a80b0b0eb8
Revises: 4d7a2e9c1b6f
Create Date: 2026-11-13 10:00:00.000000

Hand-written, matching this table's own prior migrations' note on why:
autogenerate proposes a wrong diff against it.

Who asked for the run, which every step's grant for a host's root step names.
Defaults to empty: runs created before this, and runs PMM Extensions' own
service principal created.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.extensions.apps.shared.om.config import om_schema
from app.extensions.config import extensions_settings as sep_settings


# revision identifiers, used by Alembic.
revision: str = "91a80b0b0eb8"
down_revision: Union[str, None] = "4d7a2e9c1b6f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    schema = om_schema(sep_settings.DATABASE)
    op.add_column(
        "bootstrap_run",
        sa.Column("requested_by", sa.Text(), nullable=False, server_default=""),
        schema=schema,
    )


def downgrade() -> None:
    schema = om_schema(sep_settings.DATABASE)
    op.drop_column("bootstrap_run", "requested_by", schema=schema)
