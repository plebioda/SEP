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

"""Tests for the grants a step's requests to the root step's socket helper run under."""

import base64
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from app.extensions.apps.om_bootstrap import grants
from app.extensions.apps.om_bootstrap.config import om_bootstrap_settings

#: A grant's lifetime in these tests, in seconds.
TTL_S = 900


@pytest.fixture
def key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ec.EllipticCurvePrivateKey:
    """Configure a fresh P-256 signing key, and return it."""
    private = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "grant.key"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setattr(om_bootstrap_settings, "OPERATIONS_GRANT_KEY", str(path))
    return private


def _sign(
    operations: list[str], ttl_s: int = TTL_S, requested_by: str = "alice"
) -> str | None:
    return grants.sign_grant(
        node="node00",
        run_id="run-1",
        step="start_service",
        operations=operations,
        ttl_s=ttl_s,
        requested_by=requested_by,
    )


def _split(grant: str) -> tuple[bytes, bytes]:
    payload, signature = grant.split(".")
    return base64.b64decode(payload), base64.b64decode(signature)


class TestSignGrant:
    """Assert what a grant carries and that the host's check accepts it."""

    def test_no_key_means_no_grant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Send no grant while none is configured: a host that wants one refuses."""
        monkeypatch.setattr(om_bootstrap_settings, "OPERATIONS_GRANT_KEY", "")

        assert _sign(["restart 27017"]) is None

    def test_a_step_without_requests_gets_no_grant(
        self, key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Grant nothing to a step that asks the root step for nothing."""
        assert _sign([]) is None

    def test_the_payload_names_node_run_step_expiry_and_each_request(
        self, key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Carry what the host checks: the node, the expiry, the exact requests."""
        grant = _sign(["restart 27017", "port open 27017"], ttl_s=TTL_S)

        assert grant is not None
        payload, _ = _split(grant)
        fields = [line.split("=", 1) for line in payload.decode().splitlines()]
        values = dict(fields)
        assert values["version"] == "1"
        assert values["node"] == "node00"
        assert values["run"] == "run-1"
        assert values["step"] == "start_service"
        assert values["by"] == "alice"
        assert int(values["until"]) - int(values["issued"]) == TTL_S
        assert [v for k, v in fields if k == "allow"] == [
            "restart 27017",
            "port open 27017",
        ]

    def test_the_service_principal_is_named_as_such(
        self, key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Name PMM Extensions when no user asked for the run."""
        grant = _sign(["restart 27017"], requested_by="")

        assert grant is not None
        payload, _ = _split(grant)
        assert "by=pmm-extensions" in payload.decode().splitlines()

    def test_the_signature_verifies_with_the_public_key(
        self, key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Sign the exact payload bytes, ECDSA over SHA-256."""
        grant = _sign(["restart 27017"])

        assert grant is not None
        payload, signature = _split(grant)
        key.public_key().verify(signature, payload, ec.ECDSA(hashes.SHA256()))

    @pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
    def test_openssl_verifies_it_as_the_host_does(
        self, key: ec.EllipticCurvePrivateKey, tmp_path: Path
    ) -> None:
        """Pass the check the socket helper runs: ``openssl dgst -sha256 -verify``."""
        grant = _sign(["restart 27017"])
        assert grant is not None
        payload, signature = _split(grant)
        (tmp_path / "grant").write_bytes(payload)
        (tmp_path / "signature").write_bytes(signature)
        (tmp_path / "grant.pem").write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(tmp_path / "grant.pem"),
                "-signature",
                str(tmp_path / "signature"),
                str(tmp_path / "grant"),
            ],
            capture_output=True,
            timeout=30,
            check=False,
        )

        assert result.returncode == 0, result.stderr

    def test_a_newline_cannot_add_a_request(
        self, key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Refuse a value that would turn into another line of the payload."""
        with pytest.raises(ValueError, match="newline"):
            _sign(["restart 27017\nallow=stop 27017"])

    def test_refuses_a_key_that_is_not_ecdsa(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sign only with the key type the host's check expects."""
        path = tmp_path / "ed25519.key"
        path.write_bytes(
            ed25519.Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        monkeypatch.setattr(om_bootstrap_settings, "OPERATIONS_GRANT_KEY", str(path))

        with pytest.raises(TypeError, match="not an ECDSA private key"):
            _sign(["restart 27017"])
