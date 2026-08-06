"""Minimal canonical authorization-request contract for Signed Intent.

This module preserves the v2 canonical bytes used by the TriageCore experiment
without importing the broader TriageCore runtime or capability lifecycle.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

REQUEST_SCHEMA = "triagecore.authz.request.v2"
RP_ID = "triagecore.local"
DEFAULT_REQUEST_TTL_SECONDS = 600
_RISK_CLASSES = frozenset({"low", "medium", "high"})
_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class AuthzError(ValueError):
    """The canonical request is malformed or violates a stable vocabulary."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _normalized_timestamp(value: str, field_name: str) -> str:
    try:
        return _isoformat(datetime.fromisoformat(value))
    except ValueError as exc:
        raise AuthzError(f"invalid {field_name} timestamp: {value!r}") from exc


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AuthorizationRequest:
    """Canonical, privacy-safe description of one bounded authorization."""

    decision_id: str
    artifact_byte_digest: str
    plan_body_digest: str
    task_id: str
    risk_class: str
    policy_version: str
    approver_identity_id: str
    user_verification_required: bool = True
    scope_digest: str = ""
    rp_id: str = RP_ID
    schema: str = REQUEST_SCHEMA
    nonce: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: str = field(default_factory=lambda: _isoformat(_utc_now()))
    expires_at: str = ""

    def __post_init__(self) -> None:
        if self.schema != REQUEST_SCHEMA:
            raise AuthzError(f"unsupported request schema: {self.schema!r}")
        for name in ("risk_class", "policy_version", "approver_identity_id", "rp_id"):
            value = (getattr(self, name) or "").strip().lower()
            object.__setattr__(self, name, value)
        for name in ("task_id", "decision_id"):
            value = (getattr(self, name) or "").strip()
            object.__setattr__(self, name, value)
            if not value or any(char.isspace() for char in value):
                raise AuthzError(f"{name} must be non-empty with no whitespace")
        if self.risk_class not in _RISK_CLASSES:
            raise AuthzError(f"unknown risk_class: {self.risk_class!r}")
        for name in ("policy_version", "approver_identity_id", "rp_id"):
            if not _IDENTIFIER_PATTERN.fullmatch(getattr(self, name)):
                raise AuthzError(f"{name} is not a stable governed identifier")
        for name in ("artifact_byte_digest", "plan_body_digest"):
            if not _DIGEST_PATTERN.fullmatch(getattr(self, name)):
                raise AuthzError(f"{name} must match sha256:<64 lowercase hex>")
        if self.scope_digest and not _DIGEST_PATTERN.fullmatch(self.scope_digest):
            raise AuthzError("scope_digest must be empty or sha256:<64 lowercase hex>")
        try:
            object.__setattr__(self, "nonce", str(uuid.UUID(self.nonce.strip())))
        except (AttributeError, ValueError) as exc:
            raise AuthzError(f"nonce must be a UUID: {self.nonce!r}") from exc
        object.__setattr__(self, "issued_at", _normalized_timestamp(self.issued_at, "issued_at"))
        if self.expires_at:
            object.__setattr__(self, "expires_at", _normalized_timestamp(self.expires_at, "expires_at"))
        else:
            expiry = datetime.fromisoformat(self.issued_at).timestamp() + DEFAULT_REQUEST_TTL_SECONDS
            object.__setattr__(self, "expires_at", _isoformat(datetime.fromtimestamp(expiry, tz=timezone.utc)))

    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(asdict(self))

    def request_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or _utc_now()) > datetime.fromisoformat(self.expires_at)
