"""Freeze a human-readable release intent into a canonical request."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from authorization_request import AuthorizationRequest

FULL_COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def resolve_commit(repository: Path, commit: str) -> str:
    """Return the full commit ID only if it names a commit object in the local repository."""
    commit = commit.lower()
    if not FULL_COMMIT_ID.fullmatch(commit):
        raise ValueError("--commit must be a full 40- or 64-character Git commit ID")
    # Without --no-replace-objects, a refs/replace entry can make a missing ID
    # or a blob resolve as a commit under its own ID.
    result = subprocess.run(
        [
            "git", "--no-replace-objects", "-C", str(repository),
            "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # A tag ID peels to a different commit ID, so equality also rejects tags.
    if result.returncode != 0 or result.stdout.strip() != commit:
        raise ValueError(f"--commit {commit} is not a commit in {repository}")
    return commit


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--commit", required=True, help="full Git commit ID of the release candidate; must exist in --repo"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=here,
        help="local Git repository that must contain the --commit object; not checked against GitHub",
    )
    parser.add_argument("--expires-at", required=True, help="ISO-8601 UTC expiration")
    parser.add_argument("--intent", type=Path, default=here / "release-intent.template.json")
    parser.add_argument("--scope", type=Path, default=here / "release-scope.json")
    parser.add_argument("--output", type=Path, default=here / "authorization-request.json")
    parser.add_argument("--review-output", type=Path, default=here / "release-review.json")
    return parser.parse_args()


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def main() -> int:
    args = parse_args()
    commit = resolve_commit(args.repo, args.commit)
    intent = load_json(args.intent)
    scope = load_json(args.scope)
    intent["repository"] = "coreytshaffer/triagecore-signed-intent"
    intent["ref"] = commit
    release_ref = {"repository": intent["repository"], "ref": intent["ref"]}
    request = AuthorizationRequest(
        decision_id=f"yk58-release-{commit[:16]}",
        artifact_byte_digest=digest(release_ref),
        plan_body_digest=digest(intent),
        task_id="f3c24d60-5360-41dc-9dc6-b7cbb91b68b8",
        risk_class="medium",
        policy_version="signed-intent-release-v1",
        approver_identity_id="human-corey",
        user_verification_required=False,
        scope_digest=digest(scope),
        rp_id="triagecore.local",
        nonce=str(uuid.uuid4()),
        issued_at=datetime.now(timezone.utc).isoformat(),
        expires_at=args.expires_at,
    )
    review = {"intent": intent, "scope": scope, "release_ref": release_ref}
    args.output.write_text(json.dumps(json.loads(request.canonical_bytes()), indent=2) + "\n", encoding="utf-8")
    args.review_output.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared request: {args.output}")
    print(f"Canonical request digest: {request.request_digest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
