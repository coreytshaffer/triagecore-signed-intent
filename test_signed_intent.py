from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ESP256
from authorization_request import AuthorizationRequest, REQUEST_SCHEMA
from evidence import (
    EvidenceVerificationError,
    build_evidence,
    canonical_json_digest,
    load_request,
    request_digest,
    validate_review_binding,
    verify_evidence,
    verify_signature,
)
from prepare_release_request import main as prepare_release_request, resolve_commit

DIRECTORY = Path(__file__).resolve().parent

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


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


def git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def make_release_repo(repository: Path, *init_args: str) -> Path:
    """A throwaway repository with one commit and one annotated tag; signing is off."""
    repository.mkdir()
    identity = ("-c", "user.name=Test", "-c", "user.email=test@example.invalid")
    unsigned = ("-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false")
    git(repository, "init", "--quiet", *init_args)
    (repository / "release.txt").write_text("release candidate\n", encoding="utf-8")
    git(repository, "add", "release.txt")
    git(repository, *identity, *unsigned, "commit", "--quiet", "-m", "release candidate")
    git(repository, *identity, *unsigned, "tag", "-a", "v1", "-m", "release tag")
    return repository


@pytest.fixture
def release_repo(tmp_path: Path) -> Path:
    return make_release_repo(tmp_path / "repo")


@requires_git
def test_release_commit_accepts_a_full_existing_commit_id(release_repo):
    commit = git(release_repo, "rev-parse", "HEAD")
    assert resolve_commit(release_repo, commit) == commit
    assert resolve_commit(release_repo, commit.upper()) == commit


@requires_git
def test_release_commit_accepts_a_sha256_commit_id(tmp_path):
    try:
        repository = make_release_repo(tmp_path / "sha256-repo", "--object-format=sha256")
    except subprocess.CalledProcessError:
        pytest.skip("this Git cannot create SHA-256 repositories")
    commit = git(repository, "rev-parse", "HEAD")
    assert len(commit) == 64
    assert resolve_commit(repository, commit) == commit


@requires_git
def test_release_commit_rejects_ids_that_are_not_full_commit_ids(release_repo):
    commit = git(release_repo, "rev-parse", "HEAD")
    for value in (commit[:12], commit + "a", "g" * 40):
        with pytest.raises(ValueError, match="full 40- or 64-character"):
            resolve_commit(release_repo, value)


@requires_git
def test_release_commit_rejects_ids_that_do_not_name_a_commit(release_repo):
    for value in (
        "deadbeef" * 5,
        "f" * 64,
        git(release_repo, "rev-parse", "HEAD^{tree}"),
        git(release_repo, "rev-parse", "HEAD:release.txt"),
        git(release_repo, "rev-parse", "v1"),
    ):
        with pytest.raises(ValueError, match="is not a commit"):
            resolve_commit(release_repo, value)


@requires_git
def test_prepared_request_binds_the_verified_commit(release_repo, tmp_path, monkeypatch):
    commit = git(release_repo, "rev-parse", "HEAD")
    output = tmp_path / "authorization-request.json"
    review_output = tmp_path / "release-review.json"
    monkeypatch.setattr(sys, "argv", [
        "prepare_release_request.py",
        "--commit", commit.upper(),
        "--repo", str(release_repo),
        "--expires-at", "2026-12-31T00:00:00+00:00",
        "--output", str(output),
        "--review-output", str(review_output),
    ])
    assert prepare_release_request() == 0

    review = json.loads(review_output.read_text(encoding="utf-8"))
    assert review["release_ref"]["ref"] == commit
    assert review["intent"]["ref"] == commit
    validate_review_binding(load_request(output), review)


@requires_git
def test_release_commit_ignores_git_replacement_refs(release_repo):
    """refs/replace can make a missing ID or a blob look like a commit; preparation must not."""
    commit = git(release_repo, "rev-parse", "HEAD")
    for replaced in ("deadbeef" * 5, git(release_repo, "rev-parse", "HEAD:release.txt")):
        git(release_repo, "update-ref", f"refs/replace/{replaced}", commit)
        with pytest.raises(ValueError, match="is not a commit"):
            resolve_commit(release_repo, replaced)
    assert resolve_commit(release_repo, commit) == commit


def request_binding(review: dict) -> AuthorizationRequest:
    """A test request whose digests bind exactly this review."""
    return AuthorizationRequest(
        decision_id="test-review-binding",
        artifact_byte_digest=canonical_json_digest(review["release_ref"]),
        plan_body_digest=canonical_json_digest(review["intent"]),
        scope_digest=canonical_json_digest(review["scope"]),
        task_id="f3c24d60-5360-41dc-9dc6-b7cbb91b68b8",
        risk_class="medium",
        policy_version="signed-intent-test-v1",
        approver_identity_id="test-approver",
        user_verification_required=False,
        nonce="00000000-0000-4000-8000-000000000002",
        issued_at="2026-08-05T12:00:00+00:00",
        expires_at="2026-08-06T12:00:00+00:00",
    )


def review_for(intent_ref: str, release_ref: str) -> dict:
    repository = "coreytshaffer/triagecore-signed-intent"
    return {
        "intent": {"repository": repository, "ref": intent_ref},
        "scope": {"allowed_effects": ["publish the referenced source"]},
        "release_ref": {"repository": repository, "ref": release_ref},
    }


def test_committed_release_review_still_binds():
    request = load_request(DIRECTORY / "authorization-request.json")
    review = json.loads((DIRECTORY / "release-review.json").read_text(encoding="utf-8"))
    validate_review_binding(request, review)


def test_review_binding_rejects_an_abbreviated_release_ref():
    review = review_for("78822deda7f6", "78822deda7f6")
    with pytest.raises(EvidenceVerificationError, match="not a full commit ID"):
        validate_review_binding(request_binding(review), review)


def test_review_binding_rejects_a_release_ref_that_differs_from_the_displayed_intent():
    review = review_for("a" * 40, "b" * 40)
    with pytest.raises(EvidenceVerificationError, match="does not match the displayed intent"):
        validate_review_binding(request_binding(review), review)


def test_review_binding_requires_a_named_release_repository():
    for repository in (None, ""):
        review = review_for("a" * 40, "a" * 40)
        for block in ("intent", "release_ref"):
            if repository is None:
                del review[block]["repository"]
            else:
                review[block]["repository"] = repository
        with pytest.raises(EvidenceVerificationError, match="names no repository"):
            validate_review_binding(request_binding(review), review)


def load_sample_evidence() -> dict:
    return json.loads((DIRECTORY / "authorization-evidence.json").read_text(encoding="utf-8"))


def test_committed_evidence_verifies_with_its_release_review():
    assert verify_evidence(load_sample_evidence(), enforce_expiration=False)["status"] == "verified"


def test_evidence_without_a_release_review_is_rejected():
    """The signature alone does not show what the signed digests meant."""
    evidence = load_sample_evidence()
    del evidence["review"]
    with pytest.raises(EvidenceVerificationError, match="no release review"):
        verify_evidence(evidence, enforce_expiration=False)


def test_evidence_with_a_non_object_release_review_is_rejected():
    evidence = load_sample_evidence()
    evidence["review"] = []
    with pytest.raises(EvidenceVerificationError, match="must be an object"):
        verify_evidence(evidence, enforce_expiration=False)


def test_evidence_with_an_altered_release_review_is_rejected():
    evidence = load_sample_evidence()
    evidence["review"]["intent"]["purpose"] += " (altered)"
    with pytest.raises(EvidenceVerificationError, match="intent digest"):
        verify_evidence(evidence, enforce_expiration=False)


def test_building_evidence_requires_a_release_review():
    key = ESP256.from_cryptography_key(ec.generate_private_key(ec.SECP256R1()).public_key())
    with pytest.raises(TypeError):
        build_evidence(
            build_test_request(),
            master_public_key=key,
            derived_public_key=key,
            ikm=bytes(32),
            signature=b"",
        )


SAMPLE_RELEASE_TARGET = "coreytshaffer/triagecore-signed-intent@78822deda7f65595cbe56b552e9ae20965a3c122"


def test_verification_reports_the_bound_release_target():
    summary = verify_evidence(load_sample_evidence(), enforce_expiration=False)
    assert summary["release_target"] == SAMPLE_RELEASE_TARGET


def test_verifier_prints_the_bound_release_target():
    result = subprocess.run(
        [sys.executable, str(DIRECTORY / "verify_authorization.py"), "--allow-expired"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert f"[OK] Release target bound: {SAMPLE_RELEASE_TARGET}" in result.stdout
