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

"""Define the Operations bootstrap settings section, under ``EXTENSIONS.OM_BOOTSTRAP``.

Read straight off YAML/env rather than mounted as a field on ``ExtensionsSettings``,
for the reason ``om_inventory/config.py`` gives.
"""

__all__ = ["OmBootstrapSettings", "om_bootstrap_settings"]

from typing import ClassVar

from app.core.config import BaseYamlSettings


class OmBootstrapSettings(BaseYamlSettings):
    """Configure how bootstrap steps reach a host's root step.

    YAML/env only, never settable over the API: whoever could change the key
    could sign requests for every host that trusts it.

    :cvar SETTINGS_PREFIXES: Places this section under ``EXTENSIONS.OM_BOOTSTRAP``.
    :param OPERATIONS_GRANT_KEY: Path to the ECDSA P-256 private key (PEM) that
        signs each step's grant for the root step's socket helper, whose host
        holds the public half. Empty: steps carry no grant, and a host whose
        helper requires one refuses them.
    """

    SETTINGS_PREFIXES: ClassVar[list[str]] = ["EXTENSIONS", "OM_BOOTSTRAP"]
    OPERATIONS_GRANT_KEY: str = ""


om_bootstrap_settings: OmBootstrapSettings = OmBootstrapSettings()
