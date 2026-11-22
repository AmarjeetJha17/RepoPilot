"""Application service for policy-authorized, bounded staged patching."""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from repopilot.agent.contracts import ToolCall
from repopilot.sandbox.patches import (
    DiffPreview,
    FileChangeSummary,
    PatchComparisonResult,
    PatchError,
    PatchFailure,
    PatchLimits,
    PatchProposal,
    PatchStagingResult,
    PatchStagingStatus,
    PatchValidationResult,
)
from repopilot.sandbox.read_access import WorkspaceReadAccess
from repopilot.sandbox.workspace import (
    WorkspaceError,
    WorkspaceHandle,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.sandbox.write_access import WorkspaceWriteError
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
)
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.errors import ToolRegistryError
from repopilot.tools.registry import ToolRegistry

_DEFAULT_PATCH_LIMITS = PatchLimits()


class _PolicyScope(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    paths: list[str] = Field(min_length=1, max_length=20)


class PatchStager:
    """Stage authorized full-file replacements inside one manager-owned workspace."""

    def __init__(
        self,
        manager: WorkspaceManager,
        handle: WorkspaceHandle,
        authorization: AuthorizationContext,
        *,
        limits: PatchLimits = _DEFAULT_PATCH_LIMITS,
        policy: DefaultPolicyEngine | None = None,
    ) -> None:
        self._manager = manager
        self._handle = handle
        self._authorization = authorization
        self._limits = limits
        if (
            authorization.workspace is not ExecutionWorkspace.STAGING
            or authorization.workspace_identity != workspace_identity_for_handle(handle)
            or not _same_path(authorization.workspace_root, handle.staging_root)
            or limits.max_file_bytes > manager._limits.max_file_bytes
            or limits.max_total_bytes > manager._limits.max_total_bytes
            or limits.max_files > manager._limits.max_files
        ):
            raise PatchError(PatchFailure.WORKSPACE_MISMATCH)
        arguments = _PolicyScope
        self._policy_registry = ToolRegistry(
            (
                ToolDefinition(
                    name="stage_patch",
                    description="Authorize patch paths within the trusted staging workspace.",
                    arguments_model=arguments,
                    capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
                    resource_fields=("paths",),
                ),
            )
        )
        self._policy = policy or DefaultPolicyEngine(self._policy_registry)
        self._reader: WorkspaceReadAccess = manager.read_access(handle)
        self._writer = manager.write_access(handle)

    @property
    def limits(self) -> PatchLimits:
        """Return the trusted limits used for patch validation and staging."""
        return self._limits

    def is_bound_to(self, manager: WorkspaceManager, handle: WorkspaceHandle) -> bool:
        """Check that this stager belongs to the exact manager-owned handle objects."""
        return self._manager is manager and self._handle is handle

    def validate_proposal(self, proposal: PatchProposal) -> PatchValidationResult:
        """Check shape, trusted limits, baseline eligibility, and UTF-8 without writing."""
        try:
            normalized = _parse_proposal(proposal)
            self._preflight(normalized)
        except PatchError as error:
            return PatchValidationResult(False, error.reason)
        return PatchValidationResult(True)

    def stage(self, proposal: PatchProposal) -> PatchStagingResult:
        """Freshly authorize and preflight every replacement before deterministic writes."""
        try:
            normalized = _parse_proposal(proposal)
            self._validate_shape(normalized)
            self._authorize(normalized)
            self._preflight(normalized)
        except PatchError as error:
            return PatchStagingResult(PatchStagingStatus.FAILED, reason=error.reason)

        applied: list[FileChangeSummary] = []
        for replacement in sorted(normalized.replacements, key=lambda item: item.path):
            try:
                content = replacement.content.encode("utf-8", errors="strict")
                after = self._writer.replace_bytes(
                    replacement.path,
                    expected_sha256=replacement.expected_sha256,
                    content=content,
                    max_original_bytes=self._limits.max_file_bytes,
                    max_replacement_bytes=self._limits.max_file_bytes,
                )
                applied.append(
                    FileChangeSummary(replacement.path, replacement.expected_sha256, after)
                )
            except WorkspaceWriteError as error:
                if error.replacement_applied:
                    applied.append(
                        FileChangeSummary(
                            replacement.path,
                            replacement.expected_sha256,
                            hashlib.sha256(content).hexdigest(),
                        )
                    )
                status = PatchStagingStatus.PARTIAL if applied else PatchStagingStatus.FAILED
                reason = PatchFailure.PARTIAL if applied else PatchFailure.STAGING_FAILED
                return PatchStagingResult(status, tuple(applied), reason)
            except (WorkspaceError, UnicodeEncodeError):
                status = PatchStagingStatus.PARTIAL if applied else PatchStagingStatus.FAILED
                reason = PatchFailure.PARTIAL if applied else PatchFailure.STAGING_FAILED
                return PatchStagingResult(status, tuple(applied), reason)
        return PatchStagingResult(PatchStagingStatus.STAGED, tuple(applied))

    def compare_to_baseline(self) -> PatchComparisonResult:
        """Compare current staged files to the manager-retained initial snapshot."""
        manifest = {item.path: item for item in self._handle.baseline.files}
        changed: list[str] = []
        deleted: list[str] = []
        report = self._manager.check_integrity(self._handle)
        baseline_paths = set(manifest)
        added: list[str] = []
        for change in report.changes:
            if change.kind.value == "deleted":
                deleted.append(change.path)
            elif change.kind.value == "modified" and change.path in baseline_paths:
                changed.append(change.path)
            elif change.kind.value == "unexpected" and change.path:
                added.append(change.path)
            else:
                raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE)
        return PatchComparisonResult(tuple(changed), tuple(added), tuple(deleted))

    def generate_diff(self) -> DiffPreview:
        """Create a deterministic, sanitized unified diff against the trusted baseline."""
        chunks: list[str] = []
        for item in self._handle.baseline.files:
            try:
                before = self._manager.baseline_content(self._handle, item.path).decode("utf-8")
                current = self._reader.read_bytes(
                    item.path, max_bytes=self._limits.max_file_bytes
                ).content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise PatchError(PatchFailure.INVALID_TEXT) from error
            except WorkspaceError as error:
                raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE) from error
            before_lines = before.splitlines(keepends=True)
            current_lines = current.splitlines(keepends=True)
            chunks.extend(
                difflib.unified_diff(
                    before_lines,
                    current_lines,
                    fromfile=f"a/{item.path}",
                    tofile=f"b/{item.path}",
                    n=3,
                    lineterm="\n",
                )
            )
        safe = _sanitize_diff("".join(chunks))
        encoded = safe.encode("utf-8")
        lines = safe.splitlines(keepends=True)
        truncated = (
            len(encoded) > self._limits.max_diff_bytes or len(lines) > self._limits.max_diff_lines
        )
        visible = safe
        if truncated:
            visible = _bounded_prefix(
                lines, self._limits.max_diff_lines, self._limits.max_diff_bytes
            )
        return DiffPreview(visible, truncated, len(encoded), len(lines))

    def _preflight(self, proposal: PatchProposal) -> None:
        self._validate_shape(proposal)
        integrity = self._manager.check_integrity(self._handle)
        if integrity.changes and any(
            change.kind.value not in {"modified"} for change in integrity.changes
        ):
            raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE)
        projected_total = integrity.total_bytes
        for replacement in proposal.replacements:
            replacement_bytes = replacement.content.encode("utf-8", errors="strict")
            try:
                before = self._reader.read_bytes(
                    replacement.path, max_bytes=self._limits.max_file_bytes
                )
                before.content.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise PatchError(PatchFailure.INVALID_TEXT) from error
            except WorkspaceError as error:
                raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE) from error
            current_hash = hashlib.sha256(before.content).hexdigest()
            if current_hash != replacement.expected_sha256:
                raise PatchError(PatchFailure.SOURCE_CHANGED)
            projected_total += len(replacement_bytes) - len(before.content)
            if projected_total > self._limits.max_total_bytes:
                raise PatchError(PatchFailure.LIMIT_EXCEEDED)
            if (
                _changed_line_count(before.content, replacement_bytes)
                > self._limits.max_changed_lines
            ):
                raise PatchError(PatchFailure.LIMIT_EXCEEDED)

    def _validate_shape(self, proposal: PatchProposal) -> None:
        if len(proposal.replacements) > self._limits.max_files:
            raise PatchError(PatchFailure.LIMIT_EXCEEDED)
        known = {item.path: item for item in self._handle.baseline.files}
        seen: set[str] = set()
        total = 0
        for replacement in proposal.replacements:
            path = replacement.path
            _validate_relative_path(path)
            if path in seen:
                raise PatchError(PatchFailure.INVALID_PROPOSAL)
            seen.add(path)
            baseline = known.get(path)
            if baseline is None:
                raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE)
            try:
                replacement_bytes = replacement.content.encode("utf-8", errors="strict")
                if b"\x00" in replacement_bytes:
                    raise PatchError(PatchFailure.INVALID_TEXT)
            except UnicodeEncodeError as error:
                raise PatchError(PatchFailure.INVALID_TEXT) from error
            if len(replacement_bytes) > self._limits.max_file_bytes:
                raise PatchError(PatchFailure.LIMIT_EXCEEDED)
            if baseline.size_bytes > self._limits.max_file_bytes:
                raise PatchError(PatchFailure.LIMIT_EXCEEDED)
            total += len(replacement_bytes)
            if total > self._limits.max_total_bytes:
                raise PatchError(PatchFailure.LIMIT_EXCEEDED)

    def _authorize(self, proposal: PatchProposal) -> None:
        call = ToolCall(
            id="patch-preflight",
            name="stage_patch",
            arguments={"paths": [item.path for item in proposal.replacements]},
        )
        try:
            validated = self._policy_registry.validate_call(call)
        except ToolRegistryError as error:
            raise PatchError(PatchFailure.POLICY_DENIED) from error
        decision = self._policy.authorize(
            validated,
            self._authorization,
            self._handle.staging_root,
        )
        if (
            decision.decision is not PolicyDecision.ALLOW
            or decision.call_id != call.id
            or decision.run_id != self._authorization.run_id
            or decision.capabilities != (Capability.STAGED_FILE_MODIFICATION,)
        ):
            raise PatchError(PatchFailure.POLICY_DENIED)


def _parse_proposal(proposal: PatchProposal) -> PatchProposal:
    try:
        if isinstance(proposal, PatchProposal):
            return PatchProposal.model_validate(
                proposal.model_dump(mode="python"), strict=True, extra="forbid"
            )
        return PatchProposal.model_validate(proposal, strict=True, extra="forbid")
    except (ValidationError, TypeError, ValueError) as error:
        raise PatchError(PatchFailure.INVALID_PROPOSAL) from error


def _validate_relative_path(path: str) -> None:
    from repopilot.sandbox.read_access import _relative_parts
    from repopilot.sandbox.workspace import _is_excluded, _validate_component

    try:
        parts = _relative_parts(path, allow_empty=False)
        seen: set[str] = set()
        prefix: list[str] = []
        for part in parts:
            prefix.append(part)
            _validate_component(part, seen, "/".join(prefix))
        if _is_excluded(path):
            raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE)
    except WorkspaceError as error:
        raise PatchError(PatchFailure.PATH_NOT_ELIGIBLE) from error


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=True) == right.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False


def _changed_line_count(before: bytes, after: bytes) -> int:
    old_lines = before.decode("utf-8").splitlines()
    new_lines = after.decode("utf-8").splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines)
    return sum(
        (old_end - old_start) + (new_end - new_start)
        for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes()
        if tag != "equal"
    )


def _sanitize_diff(value: str) -> str:
    return "".join(
        character
        if character in "\n\t" or (ord(character) >= 32 and not 0x7F <= ord(character) <= 0x9F)
        else f"\\x{ord(character):02x}"
        for character in value
    )


def _bounded_prefix(lines: list[str], max_lines: int, max_bytes: int) -> str:
    result: list[str] = []
    size = 0
    for line in lines:
        encoded_size = len(line.encode("utf-8"))
        if len(result) >= max_lines or size + encoded_size > max_bytes:
            break
        result.append(line)
        size += encoded_size
    return "".join(result)
