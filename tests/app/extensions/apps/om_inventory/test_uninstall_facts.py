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

"""Test the host-only removal facts an ``uninstall_check`` scan reads.

The marker read, the owned-package query and the per-path removal sizes run on the
agent's own credentials with no database login, and each is best-effort: an absent
marker, a host with no package manager, or a missing path yields ``None`` / an empty
or omitted entry rather than failing the scan.
"""

from pathlib import Path
from unittest.mock import patch

from app.extensions.apps.om_inventory.payload import probe


def test_read_marker_returns_the_recorded_run_id(tmp_path: Path) -> None:
    """Return the plaintext run id a marker records, stripped of whitespace."""
    marker = tmp_path / "mongod.om-bootstrap"
    marker.write_text("run-42\n", encoding="utf-8")

    assert probe.read_marker(str(marker)) == "run-42"


def test_read_marker_is_none_when_absent(tmp_path: Path) -> None:
    """Report a missing marker as ``None``, not an error."""
    assert probe.read_marker(str(tmp_path / "missing")) is None


def test_read_marker_is_none_when_empty(tmp_path: Path) -> None:
    """Report an empty or whitespace-only marker as ``None``, not an error."""
    marker = tmp_path / "mongod.om-bootstrap"
    marker.write_text("  \n", encoding="utf-8")

    assert probe.read_marker(str(marker)) is None


def test_removal_sizes_measures_present_paths_and_omits_absent(tmp_path: Path) -> None:
    """Size each present removal path and omit the absent ones."""
    config = tmp_path / "mongod.conf"
    config.write_bytes(b"abc")
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_bytes(b"xy")
    (data / "b").write_bytes(b"z")

    sizes = probe.removal_sizes(
        {
            "config": str(config),
            "data": str(data),
            "keyfile": None,
            "log": str(tmp_path / "missing.log"),
        }
    )

    assert sizes == {"config": 3, "data": 3}


def test_collect_owned_packages_reports_the_psmdb_family() -> None:
    """Report the installed PSMDB family and exclude a non-owned over-match."""

    def fake_query(args: list[str]) -> str | None:
        pattern = args[-1]
        if pattern == "percona-server-mongodb*":
            # The last line is a non-owned over-match the filter must drop: it lacks
            # the "-" the metapackage's dependencies carry.
            return (
                "percona-server-mongodb\n"
                "percona-server-mongodb-server\n"
                "percona-server-mongodbpro\n"
            )
        if pattern == "percona-mongodb-mongosh":
            return "percona-mongodb-mongosh\n"
        return None

    with (
        patch.object(probe.shutil, "which", side_effect=lambda name: name == "rpm"),
        patch.object(probe, "run_command", side_effect=fake_query),
    ):
        owned = probe.collect_owned_packages()

    assert owned == [
        "percona-mongodb-mongosh",
        "percona-server-mongodb",
        "percona-server-mongodb-server",
    ]


def test_collect_owned_packages_is_empty_without_a_package_manager() -> None:
    """Return an empty list on a host with no supported package manager."""
    with patch.object(probe.shutil, "which", return_value=None):
        assert probe.collect_owned_packages() == []
