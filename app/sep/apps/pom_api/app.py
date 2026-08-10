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

"""Register POM's read API as a ``BaseApp``.

The registry mounts ``api_router`` at ``/api/apps/pom_api``; that is the entire
wiring, and it is why this app needs no route registration of its own.

``requires_apps`` is the important knob here. An app's *effective* enabled state ANDs
its own with every app it names, so disabling the worker gates this app too rather
than leaving it serving an ageing snapshot behind a trigger that queues work nothing
will run.

``custom_ui`` is set because the consumer is a bespoke PMM dashboard rather than the
generic schema-driven plugin -- this API's shape (a summary envelope, grouping
counts, nested cluster documents) is not the framework's entity-list contract.
"""

from app.sep.apps.framework.base import BaseApp
from app.sep.apps.nav_icons import NavIcon
from app.sep.apps.pom_api.api_routes import router as api_router

app = BaseApp(
    name="pom_api",
    display_name="PSMDB Open Manager",
    uri_path="/pom",
    css_class="pom",
    group="diagnostics",
    nav_order=14,
    react_route="/pom",
    nav_icon=NavIcon.MONGO,
    custom_ui=True,
    api_router=api_router,
    requires_apps=("pom_worker",),
)
