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

"""Define CRUD managers for the POM worker tables."""

from app.core.db.crud import BaseSQLModelManager
from app.sep.apps.pom_worker.models import PomNode, PomRun, PomSnapshot


class PomRunManager(BaseSQLModelManager):
    """Manage :class:`PomRun` CRUD operations.

    :cvar Model: The SQLModel class this manager is responsible for.
    """

    Model = PomRun


class PomNodeManager(BaseSQLModelManager):
    """Manage :class:`PomNode` CRUD operations.

    :cvar Model: The SQLModel class this manager is responsible for.
    """

    Model = PomNode


class PomSnapshotManager(BaseSQLModelManager):
    """Manage :class:`PomSnapshot` CRUD operations.

    :cvar Model: The SQLModel class this manager is responsible for.
    """

    Model = PomSnapshot
