from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ESP256
from authorization_request import AuthorizationRequest, REQUEST_SCHEMA
from evidence import (
    EvidenceVerificationError,
    request_digest,
    verify_signature,
)

DIRECTORY = Path(__file__).resolve().parent


def build_test_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        decision_id="test-signed-intent",
        artifact_byte_digest="sha256:" + "1" * 64,
        plan_body_digest="sha256:" + "2" * 64,
        scope_digest="sha256:" + "3" * 64,
        task_id="f3c24d60-5360-41dc-9dc6-b7cbb91b68b8",
        risk_class="medium",
        policy_version="signed-intent-test-v1",
        approver_identity_id="test-approver",
        user_verification_required=False,
        nonce="00000000-0000-4000-8000-000000000001",
        issued_at="2026-08-05T12:00:00+00:00",
        expires_at="2026-08-06T12:00:00+00:00",
    )


def test_request_fixture_is_canonical_and_deterministic():
    request = build_test_request()
    assert request_digest(request) == request.request_digest()
    assert json.loads(request.canonical_bytes())["schema"] == REQUEST_SCHEMA


def test_software_signature_verifies_but_tampered_request_fails():
    """Software-only negative test; this is not YubiKey hardware evidence."""
    request = build_test_request()
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = ESP256.from_cryptography_key(private_key.public_key())
    signature = private_key.sign(request.canonical_bytes(), ec.ECDSA(hashes.SHA256()))
    verify_signature(request.canonical_bytes(), public_key, signature)

    tampered = json.loads(request.canonical_bytes())
    tampered["decision_id"] += "-tampered"
    tampered_bytes = json.dumps(
        tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    with pytest.raises(EvidenceVerificationError, match="signature verification failed"):
        verify_signature(tampered_bytes, public_key, signature)
