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

"""Test the descriptor fingerprint a repeated dispatch key must match.

The fingerprint binds every non-secret part of a dispatch -- catalogue version,
privilege, target, parameters, and a secret's reference -- so a repeat whose
descriptor drifted is refused, while a secret's bytes never enter it.
"""

from app.extensions.apps.shared.om.dispatch import descriptor_fingerprint
from app.extensions.apps.shared.om.step_contract import (
    StepContract,
    StepPrivilege,
    StepTargetKind,
)

_ROOT_NODE = StepContract(
    privilege=StepPrivilege.ROOT, target_kind=StepTargetKind.NODE, idempotent=True
)
_NONE_NODE = StepContract(
    privilege=StepPrivilege.NONE, target_kind=StepTargetKind.NODE, idempotent=True
)


def test_fingerprint_is_stable_across_parameter_order() -> None:
    """Return the same digest whatever order the parameters are given in."""
    one = descriptor_fingerprint(1, _ROOT_NODE, {"a": 1, "b": 2}, "ref-1")
    two = descriptor_fingerprint(1, _ROOT_NODE, {"b": 2, "a": 1}, "ref-1")
    assert one == two


def test_fingerprint_binds_the_privilege() -> None:
    """Separate a root step's descriptor from an unprivileged one's."""
    root = descriptor_fingerprint(1, _ROOT_NODE, {}, None)
    none = descriptor_fingerprint(1, _NONE_NODE, {}, None)
    assert root != none


def test_fingerprint_binds_the_target_kind() -> None:
    """Separate a node-targeted step's descriptor from a member-targeted one's."""
    member = StepContract(
        privilege=StepPrivilege.ROOT,
        target_kind=StepTargetKind.MEMBER,
        idempotent=True,
    )
    assert descriptor_fingerprint(1, _ROOT_NODE, {}, None) != descriptor_fingerprint(
        1, member, {}, None
    )


def test_fingerprint_binds_the_catalogue_version() -> None:
    """Separate the same step's descriptor across catalogue versions."""
    assert descriptor_fingerprint(1, _ROOT_NODE, {}, None) != descriptor_fingerprint(
        2, _ROOT_NODE, {}, None
    )


def test_fingerprint_binds_the_secret_reference() -> None:
    """Separate descriptors by their secret reference, with no secret bytes in play."""
    first = descriptor_fingerprint(1, _ROOT_NODE, {}, "ref-1")
    second = descriptor_fingerprint(1, _ROOT_NODE, {}, "ref-2")
    absent = descriptor_fingerprint(1, _ROOT_NODE, {}, None)
    assert first != second
    assert first != absent
