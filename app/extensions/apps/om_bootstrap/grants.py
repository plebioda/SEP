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

"""Sign the grant a step's requests to a host's root step socket helper run under.

A host whose root step installed a grant key runs a request from the agent only
under a grant signed with the matching private key: for that node, not expired,
naming that exact request. So code that runs as the agent but did not come from
a dispatched step, or a step's grant replayed for another request, another node
or later, is refused by the host itself.

The grant is lines of ``key=value`` (``version``, ``node``, ``run``, ``step``,
``by``, ``issued``, ``until``, then one ``allow`` per request), sent as
``base64(payload).base64(signature)``: an ECDSA P-256 signature over SHA-256,
DER-encoded, which ``openssl dgst -sha256 -verify`` checks on the host.
"""

__all__ = ["GRANT_ENV_VAR", "GRANT_SLACK_S", "sign_grant"]

import base64
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.extensions.apps.om_bootstrap.config import om_bootstrap_settings

#: Where the socket helper's client reads the grant from.
GRANT_ENV_VAR = "PMM_OPERATIONS_GRANT"

#: How long a grant outlives its step's timeout: the script waits for Nomad to
#: start it, and the step's own timeout only starts then.
GRANT_SLACK_S = 600

#: Who a grant names when PMM Extensions' own service principal asked for the run.
_SERVICE = "pmm-extensions"


def sign_grant(
    *,
    node: str,
    run_id: str,
    step: str,
    operations: list[str],
    ttl_s: int,
    requested_by: str = "",
) -> str | None:
    """Sign a grant for ``operations`` on ``node``, valid for ``ttl_s`` seconds.

    :param node: The node name the step runs on, as the host's root step recorded it.
    :param run_id: The bootstrap run.
    :param step: The step's name.
    :param operations: The exact requests the grant allows.
    :param ttl_s: How long it stays valid, in seconds.
    :param requested_by: Who asked for the run; empty for the service principal.
    :return: The grant, or ``None`` when there is nothing to grant or no key to
        sign with.
    :raises ValueError: If a value would break the payload's lines.
    :raises TypeError: If the configured key is not an ECDSA private key.
    """
    key_path = om_bootstrap_settings.OPERATIONS_GRANT_KEY
    if not operations or not key_path:
        return None
    if any("\n" in value for value in (node, run_id, step, requested_by, *operations)):
        raise ValueError("a grant value contains a newline")
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"{key_path} is not an ECDSA private key")
    now = int(time.time())
    lines = [
        "version=1",
        f"node={node}",
        f"run={run_id}",
        f"step={step}",
        f"by={requested_by or _SERVICE}",
        f"issued={now}",
        f"until={now + ttl_s}",
        *(f"allow={operation}" for operation in operations),
    ]
    payload = "".join(f"{line}\n" for line in lines).encode()
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return (
        f"{base64.b64encode(payload).decode()}.{base64.b64encode(signature).decode()}"
    )
