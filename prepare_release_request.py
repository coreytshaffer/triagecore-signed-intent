"""Freeze a human-readable release intent into a canonical request."""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from authorization_request import AuthorizationRequest


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True, help="exact reviewed release-candidate SHA")
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
    if len(args.commit) < 12 or any(char not in "0123456789abcdef" for char in args.commit.lower()):
        raise ValueError("--commit must be a Git SHA")
    intent = load_json(args.intent)
    scope = load_json(args.scope)
    intent["repository"] = "coreytshaffer/triagecore-signed-intent"
    intent["ref"] = args.commit.lower()
    release_ref = {"repository": intent["repository"], "ref": intent["ref"]}
    request = AuthorizationRequest(
        decision_id=f"yk58-release-{args.commit[:16].lower()}",
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
