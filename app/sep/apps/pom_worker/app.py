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

"""Register the POM worker as a minimal ``BaseApp``.

The registration exists for three side effects, not for a user-facing surface:

* the registry derives this package's ``celery.py`` into the worker's ``include``
  list, which is what makes :func:`~app.sep.apps.pom_worker.celery.run_pom_discovery`
  a registered task;
* the app-drain reconciler recognises ``pom_worker`` as an owner key;
* the app appears on the Apps page so collection can be switched off.

It ships no router and no UI: this is a Celery job, driven from a shell or a beat
entry. ``sidebar=False`` keeps it out of the navigation, since there is nothing to
navigate to.
"""

from app.sep.apps.framework.base import BaseApp
from app.sep.apps.nav_icons import NavIcon

app = BaseApp(
    name="pom_worker",
    display_name="POM Worker",
    uri_path="/pom_worker",
    css_class="pom",
    sidebar=False,
    nav_icon=NavIcon.MONGO,
)
