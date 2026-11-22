"""Linux integration tests for exact patch approval without live application."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from repopilot.application.patch_approval import (
    PatchApprovalService,
    repository_identity_for_handle,
)
from repopilot.application.patch_staging import PatchStager
from repopilot.sandbox.patches import (
    FileReplacement,
    PatchFailure,
    PatchProposal,
    PatchStagingResult,
    PatchStagingStatus,
)
from repopilot.sandbox.workspace import WorkspaceManager, workspace_identity_for_handle
from repopilot.security.approval import (
    ApprovalLedger,
    ApprovalReasonCode,
    TrustedApprovalDecision,
)
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    ExecutionWorkspace,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Secure workspace approval preflight requires Linux.",
    ),
]


class _Confirm:
    def __init__(self, approved: bool = True) -> None:
        self.approved = approved
        self.calls = 0

    def confirm(self, manifest, diff, *, truncated, repository_label):
        self.calls += 1
        assert not truncated
        assert manifest.entries
        assert diff
        assert repository_label
        return (
            TrustedApprovalDecision(True)
            if self.approved
            else TrustedApprovalDecision(False, ApprovalReasonCode.USER_DENIED)
        )


def _system(tmp_path: Path, *, live_allowed: bool = True):
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    staging_parent = tmp_path / "staging"
    staging_parent.mkdir()
    manager = WorkspaceManager(temp_root=staging_parent)
    handle = manager.prepare(source)
    stage_context = AuthorizationContext(
        run_id="integration-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )
    stager = PatchStager(manager, handle, stage_context)
    source_context = AuthorizationContext(
        run_id="integration-run",
        workspace_root=source,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity=repository_identity_for_handle(handle),
        allowed_capabilities=(
            frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}) if live_allowed else frozenset()
        ),
    )
    confirmer = _Confirm()
    ledger = ApprovalLedger()
    service = PatchApprovalService(
        manager,
        handle,
        stager,
        source_context,
        confirmer,
        ledger,
    )
    proposal = PatchProposal(
        replacements=(
            FileReplacement(
                path="module.py",
                operation="replace_text",
                expected_sha256=hashlib.sha256(b"VALUE = 1\n").hexdigest(),
                content="VALUE = 2\n",
            ),
        )
    )
    return source, manager, handle, stager, confirmer, ledger, service, proposal


def test_exact_patch_can_be_reviewed_but_source_remains_unchanged(tmp_path: Path) -> None:
    source, manager, handle, stager, confirmer, ledger, service, proposal = _system(tmp_path)
    try:
        staged = stager.stage(proposal)
        assert staged.status is PatchStagingStatus.STAGED

        approval = service.request_approval(proposal, staged, operation_id="operation-1")

        assert approval.approved
        assert approval.manifest is not None
        assert not hasattr(approval, "receipt")
        assert approval.manifest.entries[0].path == "module.py"
        assert (source / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
        assert (handle.staging_root / "module.py").read_text(encoding="utf-8") == "VALUE = 2\n"
        assert confirmer.calls == 1

        applied = service.apply_approved(approval.manifest)
        assert not applied.applied
        assert applied.reason is ApprovalReasonCode.LIVE_APPLICATION_DISABLED
        assert (source / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
        replay = service.apply_approved(approval.manifest)
        assert replay.reason is ApprovalReasonCode.INVALID_RECEIPT
    finally:
        manager.cleanup(handle)


def test_policy_denial_stops_before_confirmation(tmp_path: Path) -> None:
    source, manager, handle, stager, confirmer, ledger, service, proposal = _system(
        tmp_path, live_allowed=False
    )
    try:
        staged = stager.stage(proposal)
        assert staged.status is PatchStagingStatus.STAGED

        approval = service.request_approval(proposal, staged, operation_id="operation-1")

        assert not approval.approved
        assert approval.reason is ApprovalReasonCode.POLICY_DENIED
        assert confirmer.calls == 0
        assert ledger.audit_records[-1].reason is ApprovalReasonCode.POLICY_DENIED
        assert ledger.audit_records[-1].receipt_id is None
        assert (source / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    finally:
        manager.cleanup(handle)


def test_forged_source_workspace_identity_fails_before_confirmation(tmp_path: Path) -> None:
    source, manager, handle, stager, confirmer, ledger, _, proposal = _system(tmp_path)
    forged_context = AuthorizationContext(
        run_id="integration-run",
        workspace_root=source,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity=f"sha256:{'0' * 64}",
        allowed_capabilities=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )
    forged_service = PatchApprovalService(
        manager,
        handle,
        stager,
        forged_context,
        confirmer,
        ledger,
    )
    try:
        staged = stager.stage(proposal)
        assert staged.status is PatchStagingStatus.STAGED

        approval = forged_service.request_approval(proposal, staged, operation_id="operation-1")

        assert not approval.approved
        assert approval.reason is ApprovalReasonCode.SCOPE_MISMATCH
        assert confirmer.calls == 0
        assert ledger.audit_records[-1].receipt_id is None
        assert (source / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    finally:
        manager.cleanup(handle)


def test_partial_staging_is_never_presented_for_approval(tmp_path: Path) -> None:
    _, manager, handle, stager, confirmer, _, service, proposal = _system(tmp_path)
    try:
        partial = PatchStagingResult(PatchStagingStatus.PARTIAL, reason=PatchFailure.PARTIAL)
        approval = service.request_approval(proposal, partial, operation_id="operation-1")

        assert not approval.approved
        assert approval.reason is ApprovalReasonCode.PREFLIGHT_FAILED
        assert confirmer.calls == 0
    finally:
        manager.cleanup(handle)
