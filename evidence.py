"""Portable evidence helpers for the isolated YubiKey 5.8 experiment."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from fido2 import cbor
from fido2.cose import CoseKey, ESP256

from authorization_request import AuthorizationRequest, AuthzError

EVIDENCE_SCHEMA = "triagecore.preview-sign-authorization-evidence.v1"
SIGNING_CONTEXT = b"triagecore-signed-intent/v1"
ALGORITHM = "ARKG-P256 / ESP256 (-9) / SHA-256"

LIMITATIONS = [
    "YubiKey 5.8 previewSign and its tooling are beta/preview interfaces.",
    "This evidence does not establish device attestation or a YubiKey model identity.",
    "A hardware touch demonstrates credential interaction, not comprehension or informed consent.",
    "This experiment is not connected to tc run or downstream action execution.",
    "One-use capability claiming remains a separate established TriageCore mechanism.",
]


class EvidenceVerificationError(ValueError):
    """The portable evidence package failed closed."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (AuthzError, TypeError, ValueError) as exc:
        raise EvidenceVerificationError("invalid base64url evidence value") from exc


def load_request(path: Path) -> AuthorizationRequest:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"cannot read authorization request: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceVerificationError("authorization request must be a JSON object")
    try:
        return AuthorizationRequest(**value)
    except (AuthzError, TypeError, ValueError) as exc:
        raise EvidenceVerificationError(f"invalid authorization request: {exc}") from exc


def canonical_request(request: AuthorizationRequest) -> dict[str, Any]:
    return json.loads(request.canonical_bytes())


def request_digest(request: AuthorizationRequest) -> str:
    return "sha256:" + hashlib.sha256(request.canonical_bytes()).hexdigest()


def canonical_json_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_review_binding(request: AuthorizationRequest, review: Mapping[str, Any]) -> None:
    intent = review.get("intent")
    scope = review.get("scope")
    release_ref = review.get("release_ref")
    if not all(isinstance(value, dict) for value in (intent, scope, release_ref)):
        raise EvidenceVerificationError("release review is missing intent, scope, or release ref")
    if request.plan_body_digest != canonical_json_digest(intent):
        raise EvidenceVerificationError("release intent digest does not match request")
    if request.scope_digest != canonical_json_digest(scope):
        raise EvidenceVerificationError("release scope digest does not match request")
    if request.artifact_byte_digest != canonical_json_digest(release_ref):
        raise EvidenceVerificationError("release reference digest does not match request")


def encode_cose_key(key: CoseKey) -> str:
    return _b64encode(cbor.encode(dict(key)))


def decode_cose_key(value: str) -> CoseKey:
    try:
        decoded = cbor.decode(_b64decode(value))
        if not isinstance(decoded, dict):
            raise EvidenceVerificationError("COSE public key must decode to a map")
        return CoseKey.parse(decoded)
    except EvidenceVerificationError:
        raise
    except Exception as exc:
        raise EvidenceVerificationError("invalid COSE public key") from exc


def verify_signature(message: bytes, public_key: CoseKey, signature: bytes) -> None:
    if not isinstance(public_key, ESP256) or public_key.get(3) != -9:
        raise EvidenceVerificationError("derived key is not ESP256 (-9)")
    try:
        public_key.verify(message, signature)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise EvidenceVerificationError("signature verification failed") from exc


def build_evidence(
    request: AuthorizationRequest,
    *,
    master_public_key: CoseKey,
    derived_public_key: CoseKey,
    ikm: bytes,
    signature: bytes,
    review: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "request": canonical_request(request),
        "request_digest": request_digest(request),
        "signing": {
            "feature": "YubiKey 5.8 previewSign with ARKG-P256",
            "algorithm": ALGORITHM,
            "context": SIGNING_CONTEXT.decode("ascii"),
            "ikm_b64url": _b64encode(ikm),
            "master_public_key_cose_b64url": encode_cose_key(master_public_key),
            "derived_public_key_cose_b64url": encode_cose_key(derived_public_key),
            "signature_b64url": _b64encode(signature),
            "attestation": "none",
            "user_verification_required": False,
        },
        "limitations": list(LIMITATIONS),
    }
    if review is not None:
        validate_review_binding(request, review)
        evidence["review"] = dict(review)
    return evidence


def verify_evidence(
    evidence: Mapping[str, Any],
    *,
    now: datetime | None = None,
    enforce_expiration: bool = True,
) -> dict[str, str]:
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise EvidenceVerificationError("unsupported evidence schema")

    request_value = evidence.get("request")
    signing = evidence.get("signing")
    if not isinstance(request_value, dict) or not isinstance(signing, dict):
        raise EvidenceVerificationError("evidence request or signing block is missing")

    try:
        request = AuthorizationRequest(**request_value)
    except (TypeError, ValueError) as exc:
        raise EvidenceVerificationError(f"invalid evidence request: {exc}") from exc

    digest = request_digest(request)
    if evidence.get("request_digest") != digest:
        raise EvidenceVerificationError("canonical request digest mismatch")
    if enforce_expiration and request.is_expired(now):
        raise EvidenceVerificationError("authorization request is expired")
    if signing.get("algorithm") != ALGORITHM:
        raise EvidenceVerificationError("unexpected signing algorithm")
    if signing.get("context") != SIGNING_CONTEXT.decode("ascii"):
        raise EvidenceVerificationError("wrong ARKG signing context")
    if signing.get("user_verification_required") is not False:
        raise EvidenceVerificationError("unexpected user-verification claim")
    review = evidence.get("review")
    if review is not None:
        if not isinstance(review, dict):
            raise EvidenceVerificationError("release review must be an object")
        validate_review_binding(request, review)

    try:
        master = decode_cose_key(signing["master_public_key_cose_b64url"])
        derived = decode_cose_key(signing["derived_public_key_cose_b64url"])
        ikm = _b64decode(signing["ikm_b64url"])
        signature = _b64decode(signing["signature_b64url"])
    except KeyError as exc:
        raise EvidenceVerificationError(f"missing signing field: {exc.args[0]}") from exc

    if len(ikm) != 32:
        raise EvidenceVerificationError("ARKG IKM must be exactly 32 bytes")
    try:
        rederived, _ = master.derive_public_key(ikm, SIGNING_CONTEXT)
    except Exception as exc:
        raise EvidenceVerificationError("cannot derive ARKG verification key") from exc
    if dict(rederived) != dict(derived):
        raise EvidenceVerificationError("derived key does not match ARKG context and IKM")

    verify_signature(request.canonical_bytes(), derived, signature)
    return {
        "request_digest": digest,
        "expires_at": request.expires_at,
        "status": "verified",
    }


def tampered_copy(evidence: Mapping[str, Any], field: str) -> dict[str, Any]:
    value = deepcopy(dict(evidence))
    request = value.get("request")
    if not isinstance(request, dict) or field not in request:
        raise EvidenceVerificationError(f"cannot tamper missing request field: {field}")
    if field == "risk_class":
        request[field] = "high" if request[field] != "high" else "medium"
    elif isinstance(request[field], bool):
        request[field] = not request[field]
    else:
        request[field] = f"{request[field]}-tampered"
    return value
