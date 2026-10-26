"""Regression coverage for review-bearing evidence and safe verifier output.

All generated signatures use public test-only software keys. The ARKG fixture
uses internals of the pinned fido2 2.2.1 package; it is not hardware evidence.
"""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ARKG_P256_PLACEHOLDER, ES256, ESP256

from authorization_request import AuthorizationRequest
from evidence import (
    SIGNING_CONTEXT,
    EvidenceVerificationError,
    build_evidence,
    canonical_json_digest,
    canonical_request,
    encode_cose_key,
    load_request,
    request_digest,
    verify_evidence,
    verify_signature,
)

SOURCE = Path(__file__).resolve().parent

SAMPLE_NOW = datetime(2026, 8, 6, 5, tzinfo=UTC)
ABSENT = object()


def sample():
    return json.loads((SOURCE / "authorization-evidence.json").read_text())


@pytest.fixture(scope="session")
def software_keys():
    # Reproduce ARKG using test-only software material. No hardware claim.
    sk_bl = ec.derive_private_key(11, ec.SECP256R1())
    sk_kem = ec.derive_private_key(23, ec.SECP256R1())
    master = ARKG_P256_PLACEHOLDER(
        {
            1: -65537,
            3: ARKG_P256_PLACEHOLDER.ALGORITHM,
            -1: dict(ES256.from_cryptography_key(sk_bl.public_key())),
            -2: {**dict(ES256.from_cryptography_key(sk_kem.public_key())), 3: -25},
            -3: -9,
        }
    )
    ikm = bytes(range(32))
    derived, _ = master.derive_public_key(ikm, SIGNING_CONTEXT)
    ctx_prime = bytes([len(SIGNING_CONTEXT)]) + SIGNING_CONTEXT
    ikm_tau, _ = master._ARKG.kem.encaps(
        sk_kem.public_key(), ikm, b"ARKG-Derive-Key-KEM." + ctx_prime
    )
    tau = master._ARKG.bl.prf(ikm_tau, b"ARKG-Derive-Key-BL." + ctx_prime)
    private = ec.derive_private_key(
        (11 + tau) % ec.SECP256R1().group_order, ec.SECP256R1()
    )
    assert dict(ESP256.from_cryptography_key(private.public_key())) == dict(derived)
    return master, derived, ikm, private


def signed_software_evidence(review, keys):
    """Assemble an evidence envelope without using the builder under test.

    This permits valid cryptographic signatures over semantically invalid reviews.
    """
    master, derived, ikm, private = keys
    now = datetime.now(UTC)
    request = AuthorizationRequest(
        decision_id="independent-audit-only",
        task_id="independent-audit-only",
        artifact_byte_digest=canonical_json_digest(review["release_ref"]),
        plan_body_digest=canonical_json_digest(review["intent"]),
        scope_digest=canonical_json_digest(review["scope"]),
        risk_class="medium",
        policy_version="audit-test-v1",
        approver_identity_id="audit-test-key",
        user_verification_required=False,
        nonce="00000000-0000-4000-8000-000000000099",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    envelope = sample()
    envelope["request"] = canonical_request(request)
    envelope["request_digest"] = request_digest(request)
    envelope["review"] = copy.deepcopy(review)

    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    signature = private.sign(request.canonical_bytes(), ec.ECDSA(hashes.SHA256()))
    verify_signature(request.canonical_bytes(), derived, signature)
    envelope["signing"].update(
        {
            "master_public_key_cose_b64url": encode_cose_key(master),
            "derived_public_key_cose_b64url": encode_cose_key(derived),
            "ikm_b64url": b64(ikm),
            "signature_b64url": b64(signature),
        }
    )
    return envelope


@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
def test_legacy_sample_valid_in_both_modes(mode):
    assert (
        verify_evidence(sample(), now=SAMPLE_NOW, enforce_expiration=mode)["status"]
        == "verified"
    )


@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
@pytest.mark.parametrize(
    "review",
    [ABSENT, None, [], "text", 0, False, {}],
    ids=["absent", "null", "array", "string", "number", "bool", "empty-object"],
)
def test_bad_review_rejected_in_both_modes(mode, review):
    evidence = sample()
    if review is ABSENT:
        del evidence["review"]
    else:
        evidence["review"] = review
    with pytest.raises(EvidenceVerificationError):
        verify_evidence(evidence, now=SAMPLE_NOW, enforce_expiration=mode)


@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
@pytest.mark.parametrize("block", ["intent", "scope", "release_ref"])
@pytest.mark.parametrize(
    "value",
    [ABSENT, None, [], "text", 1, False],
    ids=["absent", "null", "array", "string", "number", "bool"],
)
def test_bad_review_children_rejected(mode, block, value):
    evidence = sample()
    if value is ABSENT:
        del evidence["review"][block]
    else:
        evidence["review"][block] = value
    with pytest.raises(EvidenceVerificationError):
        verify_evidence(evidence, now=SAMPLE_NOW, enforce_expiration=mode)


@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
@pytest.mark.parametrize(
    "block,field,value",
    [
        ("intent", "purpose", "changed"),
        ("scope", "allowed_effects", []),
        ("release_ref", "ref", "b" * 40),
        ("release_ref", "repository", "different/repo"),
        ("intent", "repository", "different/repo"),
        ("intent", "ref", "c" * 40),
    ],
)
def test_review_tampering_rejected(mode, block, field, value):
    evidence = sample()
    evidence["review"][block][field] = value
    with pytest.raises(EvidenceVerificationError):
        verify_evidence(evidence, now=SAMPLE_NOW, enforce_expiration=mode)


@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
@pytest.mark.parametrize(
    "defect",
    [
        "commit-mismatch",
        "repository-mismatch",
        "short-id",
        "uppercase-id",
        "empty-repository",
        "missing-repository",
        "nonstring-repository",
    ],
)
def test_valid_signature_cannot_bypass_target_constraints(mode, defect, software_keys):
    review = copy.deepcopy(sample()["review"])
    if defect == "commit-mismatch":
        review["release_ref"]["ref"] = "b" * 40
    elif defect == "repository-mismatch":
        review["release_ref"]["repository"] = "different/repo"
    elif defect in ("short-id", "uppercase-id"):
        for block in ("intent", "release_ref"):
            review[block]["ref"] = "a" * 12 if defect == "short-id" else "A" * 40
    else:
        for block in ("intent", "release_ref"):
            if defect == "missing-repository":
                del review[block]["repository"]
            else:
                review[block]["repository"] = "" if defect == "empty-repository" else 12
    evidence = signed_software_evidence(review, software_keys)
    with pytest.raises(EvidenceVerificationError):
        verify_evidence(evidence, enforce_expiration=mode)


@pytest.mark.parametrize("ref", ["a" * 40, "b" * 64], ids=["sha1", "sha256"])
@pytest.mark.parametrize("archival", [True, False], ids=["archival", "normal"])
def test_full_cli_verification_and_report(tmp_path, software_keys, ref, archival):
    review = copy.deepcopy(sample()["review"])
    for block in ("intent", "release_ref"):
        review[block]["ref"] = ref
    evidence = signed_software_evidence(review, software_keys)
    path = tmp_path / "software-test-evidence.json"
    path.write_text(json.dumps(evidence))
    args = [sys.executable, str(SOURCE / "verify_authorization.py"), str(path)]
    if archival:
        args.append("--allow-expired")
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    target = f"{review['release_ref']['repository']}@{ref}"
    assert f"[OK] Release target bound: {target}" in result.stdout
    assert ("[WARN] Expiration policy" in result.stdout) == archival
    assert ("[OK] Authorization unexpired" in result.stdout) != archival


@pytest.mark.parametrize("archival", [False, True], ids=["normal", "archival"])
@pytest.mark.parametrize(
    "bad_review",
    [ABSENT, None, [], {}, {"intent": {}}],
    ids=["absent", "null", "array", "empty", "incomplete"],
)
def test_cli_bad_review_rejects_without_success(
    tmp_path, software_keys, archival, bad_review
):
    evidence = signed_software_evidence(sample()["review"], software_keys)
    if bad_review is ABSENT:
        del evidence["review"]
    else:
        evidence["review"] = bad_review
    path = tmp_path / "bad-review.json"
    path.write_text(json.dumps(evidence))
    args = [sys.executable, str(SOURCE / "verify_authorization.py"), str(path)]
    if archival:
        args.append("--allow-expired")
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    assert result.returncode == 1
    assert "[FAIL] Verification failed:" in result.stdout
    assert "[OK]" not in result.stdout
    assert not result.stderr


@pytest.mark.parametrize("field", ["decision_id", "policy_version", "risk_class"])
@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
def test_rehashed_request_still_requires_signature(field, mode):
    evidence = sample()
    evidence["request"][field] = (
        "high" if field == "risk_class" else "audit-changed-value"
    )
    evidence["request_digest"] = request_digest(
        AuthorizationRequest(**evidence["request"])
    )
    with pytest.raises(
        EvidenceVerificationError, match="signature verification failed"
    ):
        verify_evidence(evidence, now=SAMPLE_NOW, enforce_expiration=mode)


def test_normal_expiration_remains_enforced():
    with pytest.raises(EvidenceVerificationError, match="expired"):
        verify_evidence(sample(), now=datetime(2026, 10, 26, tzinfo=UTC))


def test_builder_round_trip_requires_matching_review(software_keys):
    evidence = signed_software_evidence(sample()["review"], software_keys)
    master, derived, ikm, private = software_keys
    request = AuthorizationRequest(**evidence["request"])
    result = build_evidence(
        request,
        master_public_key=master,
        derived_public_key=derived,
        ikm=ikm,
        signature=private.sign(request.canonical_bytes(), ec.ECDSA(hashes.SHA256())),
        review=evidence["review"],
    )
    assert verify_evidence(result)["status"] == "verified"
    evidence["review"]["scope"]["allowed_effects"] = []
    with pytest.raises(EvidenceVerificationError, match="scope digest"):
        build_evidence(
            request,
            master_public_key=master,
            derived_public_key=derived,
            ikm=ikm,
            signature=b"",
            review=evidence["review"],
        )


@pytest.mark.parametrize("field", ["decision_id", "risk_class", "task_id"])
def test_tamper_mode_is_only_a_negative_test(field, tmp_path):
    path = tmp_path / "missing-review.json"
    evidence = sample()
    del evidence["review"]
    path.write_text(json.dumps(evidence))
    result = subprocess.run(
        [
            sys.executable,
            str(SOURCE / "verify_authorization.py"),
            str(path),
            "--allow-expired",
            "--tamper",
            field,
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "No authorization accepted." in result.stdout
    assert "Offline signature verified" not in result.stdout
    assert "Release target bound" not in result.stdout


@pytest.mark.parametrize("archival", [False, True], ids=["normal", "archival"])
@pytest.mark.parametrize(
    "payload,display",
    [
        (
            "example/repo\n[OK] FORGED-AUDIT-LINE",
            r"example/repo\n[OK] FORGED-AUDIT-LINE",
        ),
        (
            "example/repo\r[OK] FORGED-AUDIT-LINE",
            r"example/repo\r[OK] FORGED-AUDIT-LINE",
        ),
        (
            "example/repo\x1b[2K[OK] FORGED-AUDIT-LINE",
            r"example/repo\u001b[2K[OK] FORGED-AUDIT-LINE",
        ),
    ],
    ids=["newline", "carriage-return", "terminal-escape"],
)
def test_release_target_display_escapes_control_characters(
    tmp_path, software_keys, archival, payload, display
):
    review = copy.deepcopy(sample()["review"])
    for block in ["intent", "release_ref"]:
        review[block]["repository"] = payload
    evidence = signed_software_evidence(review, software_keys)
    path = tmp_path / "signed-control-character-target.json"
    path.write_text(json.dumps(evidence))
    args = [sys.executable, str(SOURCE / "verify_authorization.py"), str(path)]
    if archival:
        args.append("--allow-expired")
    run = subprocess.run(args, check=False, text=True, capture_output=True)
    assert run.returncode == 0, run.stdout + run.stderr
    expected = display + "@" + review["release_ref"]["ref"]
    assert f"[OK] Release target bound: {expected}" in run.stdout
    assert len(run.stdout.splitlines()) == 4
    assert "\x1b" not in run.stdout
    assert "\n[OK] FORGED-AUDIT-LINE" not in run.stdout


@pytest.mark.parametrize("mode", [True, False], ids=["normal", "archival"])
@pytest.mark.parametrize("value", [None, [], "text", 12, False])
def test_malformed_envelope_has_a_verification_error(mode, value):
    with pytest.raises(
        EvidenceVerificationError, match="evidence must be a JSON object"
    ):
        verify_evidence(value, now=SAMPLE_NOW, enforce_expiration=mode)


@pytest.mark.parametrize(
    "field",
    [
        "risk_class",
        "policy_version",
        "approver_identity_id",
        "rp_id",
        "decision_id",
        "task_id",
        "artifact_byte_digest",
        "plan_body_digest",
        "scope_digest",
        "nonce",
        "issued_at",
        "expires_at",
    ],
)
def test_invalid_request_field_type_is_reported_cleanly(field, tmp_path):
    evidence = sample()
    evidence["request"][field] = ["invalid-type"]
    with pytest.raises(EvidenceVerificationError, match="invalid evidence request"):
        verify_evidence(evidence, now=SAMPLE_NOW)

    path = tmp_path / "invalid-request.json"
    path.write_text(json.dumps(evidence["request"]), encoding="utf-8")
    with pytest.raises(
        EvidenceVerificationError, match="invalid authorization request"
    ):
        load_request(path)


@pytest.mark.parametrize(
    "field",
    [
        "master_public_key_cose_b64url",
        "derived_public_key_cose_b64url",
        "ikm_b64url",
        "signature_b64url",
    ],
)
@pytest.mark.parametrize("value", [None, 12, [], False])
def test_wrong_signing_value_type_has_a_verification_error(field, value):
    evidence = sample()
    evidence["signing"][field] = value
    with pytest.raises(EvidenceVerificationError):
        verify_evidence(evidence, now=SAMPLE_NOW)


@pytest.mark.parametrize("value", [None, [], "text", 12, False])
def test_builder_rejects_non_object_review_cleanly(value, software_keys):
    master, derived, ikm, _ = software_keys
    request = AuthorizationRequest(**sample()["request"])
    with pytest.raises(
        EvidenceVerificationError, match="release review must be an object"
    ):
        build_evidence(
            request,
            master_public_key=master,
            derived_public_key=derived,
            ikm=ikm,
            signature=b"",
            review=value,
        )


@pytest.mark.parametrize("tamper", [False, True], ids=["verify", "negative-test"])
@pytest.mark.parametrize("kind", ["null", "array", "request-field-type"])
def test_cli_malformed_envelope_has_no_traceback(tmp_path, tamper, kind):
    bad_input = None
    if kind == "array":
        bad_input = []
    elif kind == "request-field-type":
        bad_input = sample()
        bad_input["request"]["risk_class"] = ["medium"]
    path = tmp_path / "malformed-evidence.json"
    path.write_text(json.dumps(bad_input), encoding="utf-8")
    args = [sys.executable, str(SOURCE / "verify_authorization.py"), str(path)]
    if tamper:
        args.extend(["--tamper", "decision_id"])
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    assert result.returncode == (0 if tamper else 1)
    assert not result.stderr
    assert "Offline signature verified" not in result.stdout
    assert "Release target bound" not in result.stdout
    if tamper:
        assert "No authorization accepted." in result.stdout
    else:
        assert "[FAIL] Verification failed:" in result.stdout
