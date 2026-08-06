"""Verify or negatively test a portable Signed Intent evidence package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .evidence import (
        EvidenceVerificationError,
        tampered_copy,
        verify_evidence,
    )
except ImportError:  # Direct script execution from this directory.
    from evidence import (  # type: ignore[no-redef]
        EvidenceVerificationError,
        tampered_copy,
        verify_evidence,
    )


def parse_args() -> argparse.Namespace:
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "evidence",
        nargs="?",
        type=Path,
        default=directory / "authorization-evidence.json",
    )
    parser.add_argument(
        "--tamper",
        choices=("decision_id", "risk_class", "task_id"),
        help="modify one request field in memory and require rejection",
    )
    parser.add_argument(
        "--allow-expired",
        action="store_true",
        help="verify archived cryptography without enforcing current expiration",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[FAIL] Cannot read evidence: {exc}")
        return 2

    if args.tamper:
        try:
            verify_evidence(
                tampered_copy(evidence, args.tamper),
                enforce_expiration=not args.allow_expired,
            )
        except EvidenceVerificationError as exc:
            print(f"[OK] Tampered request rejected: {exc}")
            print("No authorization accepted.")
            return 0
        print("[FAIL] Tampered request was accepted unexpectedly")
        return 1

    try:
        summary = verify_evidence(
            evidence, enforce_expiration=not args.allow_expired
        )
    except EvidenceVerificationError as exc:
        print(f"[FAIL] Verification failed: {exc}")
        return 1
    print("[OK] Offline signature verified")
    print(f"[OK] Request digest matched: {summary['request_digest']}")
    if args.allow_expired:
        print("[WARN] Expiration policy was not enforced (archival verification mode)")
    else:
        print(f"[OK] Authorization unexpired through {summary['expires_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
