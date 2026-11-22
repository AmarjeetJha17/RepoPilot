"""Exact-action approval contracts and process-local one-time receipts.

Receipts prove that trusted application code recorded a local confirmation for one
manifest. They are not durable across processes and are not execution permissions.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4


class ApprovalReasonCode(StrEnum):
    """Content-minimized approval and preflight outcomes."""

    USER_DENIED = "user_denied"
    NONINTERACTIVE = "noninteractive"
    PREVIEW_TRUNCATED = "preview_truncated"
    INVALID_MANIFEST = "invalid_manifest"
    POLICY_DENIED = "policy_denied"
    REPOSITORY_CHANGED = "repository_changed"
    PATCH_CHANGED = "patch_changed"
    SCOPE_MISMATCH = "scope_mismatch"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    LIVE_APPLICATION_DISABLED = "live_application_disabled"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    INVALID_RECEIPT = "invalid_receipt"
    MANIFEST_CHANGED = "manifest_changed"
    CANCELLED = "cancelled"
    PREFLIGHT_FAILED = "preflight_failed"


class ApprovalConsumptionState(StrEnum):
    """State returned from attempting to consume an approval receipt."""

    CONSUMED = "consumed"
    EXPIRED = "expired"
    REJECTED = "rejected"
    REPLAYED = "replayed"


class ApprovalAuditStatus(StrEnum):
    """Safe event categories for process-local approval audit records."""

    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class PatchManifestEntry:
    """One existing file's expected source and replacement hashes."""

    path: str
    expected_source_sha256: str
    replacement_sha256: str

    def __post_init__(self) -> None:
        if not _valid_relative_path(self.path):
            raise ValueError("Manifest path must be normalized and relative.")
        if not _HASH.fullmatch(self.expected_source_sha256) or not _HASH.fullmatch(
            self.replacement_sha256
        ):
            raise ValueError("Manifest hashes must be lowercase SHA-256 hex digests.")


@dataclass(frozen=True, slots=True)
class ReviewedPatchManifest:
    """Canonical exact-action description reviewed by the local user."""

    run_id: str
    operation_id: str
    repository_identity: str
    staging_workspace_identity: str
    entries: tuple[PatchManifestEntry, ...]
    diff_digest: str
    limits: tuple[int, ...]
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not _valid_label(self.run_id) or not _valid_label(self.operation_id):
            raise ValueError("Manifest identifiers must be non-empty safe labels.")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.repository_identity):
            raise ValueError("Repository identity must be a SHA-256 identity.")
        if not _valid_label(self.staging_workspace_identity):
            raise ValueError("Staging workspace identity must be a safe label.")
        if (
            not isinstance(self.entries, tuple)
            or not self.entries
            or len(self.entries) > 20
            or any(not isinstance(entry, PatchManifestEntry) for entry in self.entries)
            or tuple(sorted(self.entries, key=lambda entry: entry.path)) != self.entries
            or len({entry.path for entry in self.entries}) != len(self.entries)
        ):
            raise ValueError("Manifest entries must be sorted, unique, and bounded.")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.diff_digest):
            raise ValueError("Diff digest must be a SHA-256 identity.")
        if (
            not isinstance(self.limits, tuple)
            or len(self.limits) != 6
            or any(type(limit) is not int or limit < 1 for limit in self.limits)
        ):
            raise ValueError("Manifest limits must be positive integers.")
        created = _as_utc(self.created_at)
        expires = _as_utc(self.expires_at)
        if expires <= created:
            raise ValueError("Manifest expiration must follow its creation time.")

    @property
    def patch_digest(self) -> str:
        """Digest of the ordered paths and expected/replacement content hashes."""
        return _sha256([_entry_dict(entry) for entry in self.entries])

    def canonical_json(self) -> str:
        """Stable serialized form binding every security-relevant manifest field."""
        return json.dumps(
            {
                "schema": "repopilot.reviewed-patch-manifest.v1",
                "run_id": self.run_id,
                "operation_id": self.operation_id,
                "repository_identity": self.repository_identity,
                "staging_workspace_identity": self.staging_workspace_identity,
                "entries": [_entry_dict(entry) for entry in self.entries],
                "patch_digest": self.patch_digest,
                "diff_digest": self.diff_digest,
                "limits": list(self.limits),
                "created_at": _as_utc(self.created_at).isoformat(),
                "expires_at": _as_utc(self.expires_at).isoformat(),
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def digest(self) -> str:
        """SHA-256 over canonical JSON; this does not itself prove consent."""
        return _sha256(self.canonical_json())


@dataclass(frozen=True, slots=True)
class TrustedApprovalDecision:
    """Decision returned only by a trusted local confirmation adapter."""

    approved: bool
    reason: ApprovalReasonCode | None = None

    def __post_init__(self) -> None:
        if (
            type(self.approved) is not bool
            or (self.approved and self.reason is not None)
            or (not self.approved and self.reason is None)
        ):
            raise ValueError("Approval decision must have a consistent outcome and reason.")


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    """Opaque in-process reference issued after trusted confirmation."""

    receipt_id: str
    manifest_digest: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalValidationResult:
    """Result of consuming an approval receipt, without sensitive details."""

    valid: bool
    state: ApprovalConsumptionState
    reason: ApprovalReasonCode | None = None


@dataclass(frozen=True, slots=True)
class ApprovalAuditRecord:
    """Content-minimized metadata for one approval lifecycle event."""

    run_id: str
    operation_id: str
    receipt_id: str | None
    timestamp: datetime
    status: ApprovalAuditStatus
    reason: ApprovalReasonCode | None
    manifest_digest: str


class ApprovalLedger:
    """Instance-local receipt ledger; not crash-safe or cross-process replay protection."""

    def __init__(self) -> None:
        self._receipts: dict[str, tuple[ApprovalReceipt, ReviewedPatchManifest, bool]] = {}
        self._audit: list[ApprovalAuditRecord] = []
        self._lock = threading.RLock()

    @property
    def audit_records(self) -> tuple[ApprovalAuditRecord, ...]:
        """Immutable view of in-memory, content-minimized audit metadata."""
        with self._lock:
            return tuple(self._audit)

    def _issue(self, manifest: ReviewedPatchManifest, now: datetime) -> ApprovalReceipt:
        """Issue only from trusted application code after local affirmative consent."""
        if not isinstance(manifest, ReviewedPatchManifest):
            raise TypeError("A reviewed patch manifest is required.")
        issued_at = _as_utc(now)
        if issued_at >= manifest.expires_at:
            raise ValueError("Cannot issue an already expired approval.")
        receipt = ApprovalReceipt(str(uuid4()), manifest.digest, issued_at, manifest.expires_at)
        with self._lock:
            self._receipts[receipt.receipt_id] = (receipt, manifest, False)
            self._audit.append(
                _audit(manifest, receipt, issued_at, ApprovalAuditStatus.APPROVED, None)
            )
        return receipt

    def _record_denial(
        self,
        manifest: ReviewedPatchManifest,
        now: datetime,
        reason: ApprovalReasonCode,
    ) -> None:
        """Record a safe refusal without storing patch content."""
        with self._lock:
            self._audit.append(
                _audit(manifest, None, _as_utc(now), ApprovalAuditStatus.DENIED, reason)
            )

    def _record_preflight_denial(
        self,
        run_id: str,
        operation_id: str,
        now: datetime,
        reason: ApprovalReasonCode,
    ) -> None:
        """Record a pre-manifest refusal using only sanitized identifiers and a safe reason."""
        safe_run = run_id if _valid_label(run_id) else "redacted"
        safe_operation = operation_id if _valid_label(operation_id) else "redacted"
        with self._lock:
            self._audit.append(
                ApprovalAuditRecord(
                    safe_run,
                    safe_operation,
                    None,
                    _as_utc(now),
                    ApprovalAuditStatus.DENIED,
                    reason,
                    "",
                )
            )

    def consume(
        self,
        receipt: ApprovalReceipt,
        manifest: ReviewedPatchManifest,
        now: datetime,
    ) -> ApprovalValidationResult:
        """Atomically reserve one receipt for one exact-manifest apply attempt."""
        if not isinstance(receipt, ApprovalReceipt) or not isinstance(
            manifest, ReviewedPatchManifest
        ):
            return ApprovalValidationResult(
                False, ApprovalConsumptionState.REJECTED, ApprovalReasonCode.INVALID_RECEIPT
            )
        current = _as_utc(now)
        with self._lock:
            stored = self._receipts.get(receipt.receipt_id)
            if stored is None or stored[0] is not receipt:
                return ApprovalValidationResult(
                    False,
                    ApprovalConsumptionState.REJECTED,
                    ApprovalReasonCode.INVALID_RECEIPT,
                )
            if stored[2]:
                return ApprovalValidationResult(
                    False, ApprovalConsumptionState.REPLAYED, ApprovalReasonCode.REPLAYED
                )
            self._receipts[receipt.receipt_id] = (stored[0], stored[1], True)
            if current >= receipt.expires_at:
                reason = ApprovalReasonCode.EXPIRED
                state = ApprovalConsumptionState.EXPIRED
            elif receipt.manifest_digest != manifest.digest or stored[1].digest != manifest.digest:
                reason = ApprovalReasonCode.MANIFEST_CHANGED
                state = ApprovalConsumptionState.REJECTED
            elif current < receipt.issued_at:
                reason = ApprovalReasonCode.INVALID_RECEIPT
                state = ApprovalConsumptionState.REJECTED
            else:
                reason = None
                state = ApprovalConsumptionState.CONSUMED
            self._audit.append(
                _audit(
                    stored[1],
                    receipt,
                    current,
                    (
                        ApprovalAuditStatus.CONSUMED
                        if reason is None
                        else ApprovalAuditStatus.REJECTED
                    ),
                    reason,
                )
            )
            return ApprovalValidationResult(reason is None, state, reason)


_HASH = re.compile(r"^[0-9a-f]{64}$")


def _valid_label(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None
    )


def _valid_relative_path(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
        or not value.isprintable()
        or ":" in value
    ):
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts) and not value.startswith("/")


def _as_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Approval timestamps must be timezone-aware.")
    return value.astimezone(UTC)


def _entry_dict(entry: PatchManifestEntry) -> dict[str, str]:
    return {
        "path": entry.path,
        "expected_source_sha256": entry.expected_source_sha256,
        "replacement_sha256": entry.replacement_sha256,
    }


def _sha256(value: object) -> str:
    if isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _audit(
    manifest: ReviewedPatchManifest,
    receipt: ApprovalReceipt | None,
    timestamp: datetime,
    status: ApprovalAuditStatus,
    reason: ApprovalReasonCode | None,
) -> ApprovalAuditRecord:
    return ApprovalAuditRecord(
        manifest.run_id,
        manifest.operation_id,
        None if receipt is None else receipt.receipt_id,
        timestamp,
        status,
        reason,
        manifest.digest,
    )
