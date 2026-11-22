"""Read-only preflight and exact-action consent for staged patch proposals.

This module deliberately has no live filesystem writer. Receipt consumption is
implemented, but source application remains disabled until its Linux mutation
and recovery guarantees are independently established.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from repopilot.agent.contracts import ToolCall
from repopilot.application.patch_staging import PatchStager
from repopilot.sandbox.patches import (
    DiffPreview,
    FileReplacement,
    PatchError,
    PatchProposal,
    PatchStagingResult,
    PatchStagingStatus,
)
from repopilot.sandbox.workspace import (
    _CLOEXEC,
    _DIRECTORY,
    _NOATIME,
    _NOFOLLOW,
    WorkspaceError,
    WorkspaceHandle,
    WorkspaceManager,
    _is_excluded,
    _mount_points_under,
    _open_absolute_directory,
    _read_mount_points,
)
from repopilot.security.approval import (
    ApprovalConsumptionState,
    ApprovalLedger,
    ApprovalReasonCode,
    ApprovalReceipt,
    ApprovalValidationResult,
    PatchManifestEntry,
    ReviewedPatchManifest,
    TrustedApprovalDecision,
)
from repopilot.security.capabilities import Capability
from repopilot.security.paths import (
    DEFAULT_SENSITIVE_PATTERNS,
    PathAuthorizationError,
    authorize_resource_path,
)
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
    PolicyReasonCode,
)
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.errors import ToolRegistryError
from repopilot.tools.registry import ToolRegistry


class ApprovalConfirmer(Protocol):
    """Trusted local confirmation boundary; model and repository data cannot implement consent."""

    def confirm(
        self,
        manifest: ReviewedPatchManifest,
        diff: str,
        *,
        truncated: bool,
        repository_label: str,
    ) -> TrustedApprovalDecision:
        """Return the outcome of a local interactive confirmation."""
        ...


class _LivePatchScope(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    paths: list[str] = Field(min_length=1, max_length=20)


class PatchApprovalError(ValueError):
    """Safe approval-preflight failure with a stable reason code only."""

    def __init__(self, reason: ApprovalReasonCode) -> None:
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    """Result of complete read-only preflight and trusted consent."""

    approved: bool
    reason: ApprovalReasonCode | None
    manifest: ReviewedPatchManifest | None = None


@dataclass(frozen=True, slots=True)
class LiveApplicationResult:
    """Fail-closed apply result; this version never mutates source files."""

    applied: bool
    reason: ApprovalReasonCode | None
    consumption: ApprovalValidationResult
    applied_paths: tuple[str, ...] = ()


class PatchApprovalService:
    """Bind an interactive approval to the complete, policy-authorized staged patch."""

    def __init__(
        self,
        manager: WorkspaceManager,
        handle: WorkspaceHandle,
        stager: PatchStager,
        authorization: AuthorizationContext,
        confirmer: ApprovalConfirmer,
        ledger: ApprovalLedger,
        *,
        policy: DefaultPolicyEngine | None = None,
        clock: Callable[[], datetime] | None = None,
        approval_ttl: timedelta = timedelta(minutes=2),
    ) -> None:
        self._manager = manager
        self._handle = handle
        self._stager = stager
        self._authorization = authorization
        self._confirmer = confirmer
        self._ledger = ledger
        self._receipts: dict[str, tuple[str, ApprovalReceipt]] = {}
        self._clock = clock or (lambda: datetime.now(UTC))
        if approval_ttl <= timedelta(0):
            raise ValueError("Approval lifetime must be positive.")
        self._approval_ttl = approval_ttl
        self._registry = ToolRegistry(
            (
                ToolDefinition(
                    name="approve_live_patch",
                    description="Authorize the exact paths in a live patch proposal.",
                    arguments_model=_LivePatchScope,
                    capabilities=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
                    resource_fields=("paths",),
                ),
            )
        )
        self._policy = policy or DefaultPolicyEngine(self._registry)

    def request_approval(
        self,
        proposal: PatchProposal,
        staging_result: PatchStagingResult,
        *,
        operation_id: str,
    ) -> ApprovalOutcome:
        """Revalidate stage and source, require policy approval, then ask the local user."""
        now = _utc_now(self._clock())
        try:
            manifest, preview, repository_label = self._preflight(
                proposal, staging_result, operation_id, now
            )
        except PatchApprovalError as error:
            self._ledger._record_preflight_denial(
                self._authorization.run_id, operation_id, now, error.reason
            )
            return ApprovalOutcome(False, error.reason)
        try:
            decision = self._confirmer.confirm(
                manifest,
                preview.text,
                truncated=preview.truncated,
                repository_label=repository_label,
            )
        except Exception:
            self._ledger._record_denial(manifest, now, ApprovalReasonCode.USER_DENIED)
            return ApprovalOutcome(False, ApprovalReasonCode.USER_DENIED, manifest)
        if not isinstance(decision, TrustedApprovalDecision):
            self._ledger._record_denial(manifest, now, ApprovalReasonCode.USER_DENIED)
            return ApprovalOutcome(False, ApprovalReasonCode.USER_DENIED, manifest)
        if not decision.approved:
            reason = decision.reason or ApprovalReasonCode.USER_DENIED
            self._ledger._record_denial(manifest, now, reason)
            return ApprovalOutcome(False, reason, manifest)
        try:
            receipt = self._ledger._issue(manifest, _utc_now(self._clock()))
        except (TypeError, ValueError):
            self._ledger._record_denial(
                manifest, _utc_now(self._clock()), ApprovalReasonCode.EXPIRED
            )
            return ApprovalOutcome(False, ApprovalReasonCode.EXPIRED, manifest)
        self._receipts[manifest.operation_id] = (manifest.digest, receipt)
        return ApprovalOutcome(True, None, manifest)

    def apply_approved(
        self, manifest: ReviewedPatchManifest, *, now: datetime | None = None
    ) -> LiveApplicationResult:
        """Consume the private receipt for one attempt; source mutation remains disabled."""
        stored = self._receipts.pop(manifest.operation_id, None)
        if stored is None:
            invalid = ApprovalValidationResult(
                False,
                ApprovalConsumptionState.REJECTED,
                ApprovalReasonCode.INVALID_RECEIPT,
            )
            return LiveApplicationResult(False, invalid.reason, invalid)
        _, receipt = stored
        return LivePatchApplicationService(self._ledger).apply(
            receipt,
            manifest,
            now=now,
        )

    def _preflight(
        self,
        proposal: PatchProposal,
        staging_result: PatchStagingResult,
        operation_id: str,
        now: datetime,
    ) -> tuple[ReviewedPatchManifest, DiffPreview, str]:
        if not sys.platform.startswith("linux"):
            raise PatchApprovalError(ApprovalReasonCode.UNSUPPORTED_PLATFORM)
        try:
            active = self._manager.cleanup_state(self._handle).value == "active"
        except WorkspaceError:
            active = False
        if not self._stager.is_bound_to(self._manager, self._handle) or not active:
            raise PatchApprovalError(ApprovalReasonCode.SCOPE_MISMATCH)
        if staging_result.status is not PatchStagingStatus.STAGED:
            raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
        if not operation_id or operation_id != operation_id.strip():
            raise PatchApprovalError(ApprovalReasonCode.INVALID_MANIFEST)
        if len({item.path for item in proposal.replacements}) != len(proposal.replacements):
            raise PatchApprovalError(ApprovalReasonCode.PATCH_CHANGED)
        baseline = {item.path: item for item in self._handle.baseline.files}
        if len(proposal.replacements) > self._stager.limits.max_files:
            raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
        replacement_bytes = 0
        for item in proposal.replacements:
            baseline_file = baseline.get(item.path)
            try:
                content = item.content.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED) from None
            replacement_bytes += len(content)
            if (
                baseline_file is None
                or baseline_file.sha256 != item.expected_sha256
                or baseline_file.size_bytes > self._stager.limits.max_file_bytes
                or len(content) > self._stager.limits.max_file_bytes
            ):
                raise PatchApprovalError(ApprovalReasonCode.PATCH_CHANGED)
        if replacement_bytes > self._stager.limits.max_total_bytes:
            raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
        replacements = {item.path: item for item in proposal.replacements}
        expected_summaries = {
            path: (item.expected_sha256, hashlib.sha256(item.content.encode("utf-8")).hexdigest())
            for path, item in replacements.items()
        }
        actual_summaries = {
            item.path: (item.before_sha256, item.after_sha256) for item in staging_result.applied
        }
        if (
            len(actual_summaries) != len(staging_result.applied)
            or actual_summaries != expected_summaries
        ):
            raise PatchApprovalError(ApprovalReasonCode.PATCH_CHANGED)
        try:
            comparison = self._stager.compare_to_baseline()
            preview = self._stager.generate_diff()
        except (PatchError, WorkspaceError):
            raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED) from None
        expected_paths = tuple(sorted(replacements))
        if (
            comparison.added_paths
            or comparison.deleted_paths
            or comparison.changed_paths != expected_paths
        ):
            raise PatchApprovalError(ApprovalReasonCode.PATCH_CHANGED)
        if preview.truncated:
            raise PatchApprovalError(ApprovalReasonCode.PREVIEW_TRUNCATED)
        repository_identity, repository_label = _repository_identity(self._handle)
        if (
            self._authorization.workspace is not ExecutionWorkspace.SOURCE
            or self._authorization.workspace_root != self._handle.source_root
            or self._authorization.workspace_identity != repository_identity
        ):
            raise PatchApprovalError(ApprovalReasonCode.SCOPE_MISMATCH)
        self._authorize_live_paths(operation_id, expected_paths)
        _verify_source_files(
            self._handle,
            replacements,
            self._stager.limits.max_file_bytes,
            self._stager.limits.max_total_bytes,
        )
        entries = tuple(
            PatchManifestEntry(path, item.expected_sha256, expected_summaries[path][1])
            for path, item in sorted(replacements.items())
        )
        manifest = ReviewedPatchManifest(
            run_id=self._authorization.run_id,
            operation_id=operation_id,
            repository_identity=repository_identity,
            staging_workspace_identity=f"workspace:{self._handle.identity.value}",
            entries=entries,
            diff_digest=_hash(preview.text.encode("utf-8")),
            limits=self._stager.limits.as_tuple(),
            created_at=now,
            expires_at=now + self._approval_ttl,
        )
        return manifest, preview, repository_label

    def _authorize_live_paths(self, operation_id: str, paths: tuple[str, ...]) -> None:
        try:
            validated = self._registry.validate_call(
                ToolCall(
                    id=operation_id,
                    name="approve_live_patch",
                    arguments={"paths": list(paths)},
                )
            )
        except (ToolRegistryError, ValueError):
            raise PatchApprovalError(ApprovalReasonCode.POLICY_DENIED) from None
        decision = self._policy.authorize(
            validated,
            self._authorization,
            self._handle.source_root,
        )
        if decision.decision is PolicyDecision.DENY:
            trusted_scope = (
                decision.run_id == self._authorization.run_id
                and decision.call_id == operation_id
                and decision.capabilities == (Capability.LIVE_REPOSITORY_MODIFICATION,)
                and decision.approval_request is None
            )
            reason = (
                _approval_reason_for_policy_denial(decision.reason_code)
                if trusted_scope
                else ApprovalReasonCode.POLICY_DENIED
            )
            raise PatchApprovalError(reason)
        if (
            decision.decision is not PolicyDecision.REQUIRE_APPROVAL
            or decision.run_id != self._authorization.run_id
            or decision.call_id != operation_id
            or decision.approval_request is None
            or decision.approval_request.workspace_identity
            != self._authorization.workspace_identity
        ):
            raise PatchApprovalError(ApprovalReasonCode.POLICY_DENIED)


_RESOURCE_SCOPE_POLICY_REASONS = frozenset(
    {
        PolicyReasonCode.INVALID_RESOURCE_PATH,
        PolicyReasonCode.RESOURCE_OUTSIDE_WORKSPACE,
        PolicyReasonCode.SENSITIVE_RESOURCE,
        PolicyReasonCode.RESOURCE_TYPE_MISMATCH,
        PolicyReasonCode.RESOURCE_NOT_FOUND,
        PolicyReasonCode.SYMLINK_NOT_ALLOWED,
    }
)


def _approval_reason_for_policy_denial(reason: PolicyReasonCode) -> ApprovalReasonCode:
    """Preserve verified resource-scope denials without reclassifying policy failures."""
    if reason in _RESOURCE_SCOPE_POLICY_REASONS:
        return ApprovalReasonCode.SCOPE_MISMATCH
    return ApprovalReasonCode.POLICY_DENIED


class LivePatchApplicationService:
    """Consume an exact approval once, then fail closed without source mutation."""

    def __init__(self, ledger: ApprovalLedger) -> None:
        self._ledger = ledger

    def apply(
        self,
        receipt: ApprovalReceipt,
        manifest: ReviewedPatchManifest,
        *,
        now: datetime | None = None,
    ) -> LiveApplicationResult:
        """Reserve the receipt and report that source application is not implemented."""
        consumed = self._ledger.consume(receipt, manifest, now or datetime.now(UTC))
        if not consumed.valid:
            return LiveApplicationResult(False, consumed.reason, consumed)
        return LiveApplicationResult(
            False,
            ApprovalReasonCode.LIVE_APPLICATION_DISABLED,
            ApprovalValidationResult(True, ApprovalConsumptionState.CONSUMED),
        )


def _repository_identity(handle: WorkspaceHandle) -> tuple[str, str]:
    root_fd = -1
    try:
        root_fd = _open_absolute_directory(handle.source_root)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise OSError("unsupported root")
        label = str(handle.source_root)
        value = f"{label}\0{root_stat.st_dev}\0{root_stat.st_ino}".encode()
        return _hash(value), label
    except (OSError, ValueError, WorkspaceError):
        raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED) from None
    finally:
        if root_fd >= 0:
            os.close(root_fd)


def repository_identity_for_handle(handle: WorkspaceHandle) -> str:
    """Return a non-secret source-root identity for trusted authorization contexts."""
    return _repository_identity(handle)[0]


def _verify_source_files(
    handle: WorkspaceHandle,
    replacements: dict[str, FileReplacement],
    max_file_bytes: int,
    max_total_bytes: int,
) -> None:
    root_fd = -1
    try:
        root_fd = _open_absolute_directory(handle.source_root)
        root_device = os.fstat(root_fd).st_dev
        if _mount_points_under(handle.source_root, _read_mount_points()):
            raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
        total_bytes = 0
        for relative, replacement in sorted(replacements.items()):
            try:
                authorize_resource_path(
                    handle.source_root,
                    relative,
                    resource_type="file",
                    sensitive_patterns=DEFAULT_SENSITIVE_PATTERNS,
                    allow_missing=False,
                    forbid_symlinks=True,
                )
            except PathAuthorizationError as error:
                reason = (
                    ApprovalReasonCode.SCOPE_MISMATCH
                    if error.failure.value in {"sensitive", "outside", "invalid", "symlink"}
                    else ApprovalReasonCode.PREFLIGHT_FAILED
                )
                raise PatchApprovalError(reason) from None
            if _is_excluded(relative):
                raise PatchApprovalError(ApprovalReasonCode.SCOPE_MISMATCH)
            parts = relative.split("/")
            parent_fd = os.dup(root_fd)
            try:
                for component in parts[:-1]:
                    next_fd = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                        dir_fd=parent_fd,
                    )
                    os.close(parent_fd)
                    parent_fd = next_fd
                    if os.fstat(parent_fd).st_dev != root_device:
                        raise PatchApprovalError(ApprovalReasonCode.SCOPE_MISMATCH)
                file_fd = os.open(
                    parts[-1],
                    os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NOATIME,
                    dir_fd=parent_fd,
                )
                try:
                    before = os.fstat(file_fd)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1
                        or before.st_dev != root_device
                        or before.st_size > max_file_bytes
                    ):
                        raise PatchApprovalError(ApprovalReasonCode.SCOPE_MISMATCH)
                    content = bytearray()
                    while len(content) <= max_file_bytes:
                        chunk = os.read(file_fd, min(65_536, max_file_bytes + 1 - len(content)))
                        if not chunk:
                            break
                        content.extend(chunk)
                    after = os.fstat(file_fd)
                    if _stat_identity(before) != _stat_identity(after):
                        raise PatchApprovalError(ApprovalReasonCode.REPOSITORY_CHANGED)
                    if len(content) > max_file_bytes:
                        raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
                    total_bytes += len(content)
                    if total_bytes > max_total_bytes:
                        raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
                    if hashlib.sha256(content).hexdigest() != replacement.expected_sha256:
                        raise PatchApprovalError(ApprovalReasonCode.REPOSITORY_CHANGED)
                    try:
                        content.decode("utf-8", errors="strict")
                        replacement.content.encode("utf-8", errors="strict")
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED) from None
                finally:
                    os.close(file_fd)
            finally:
                os.close(parent_fd)
    except PatchApprovalError:
        raise
    except (OSError, ValueError, WorkspaceError):
        raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED) from None
    finally:
        if root_fd >= 0:
            os.close(root_fd)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _hash(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _utc_now(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PatchApprovalError(ApprovalReasonCode.PREFLIGHT_FAILED)
    return value.astimezone(UTC)
