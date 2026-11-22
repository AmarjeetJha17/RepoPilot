"""Linux security tests for source preflight and exact local approval."""

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
from repopilot.sandbox.patches import FileReplacement, PatchProposal, PatchStagingStatus
from repopilot.sandbox.workspace import WorkspaceManager, workspace_identity_for_handle
from repopilot.security.approval import ApprovalLedger, ApprovalReasonCode, TrustedApprovalDecision
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, ExecutionWorkspace

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Secure source preflight requires Linux descriptor-relative operations.",
    ),
]


class _NeverConfirm:
    calls = 0

    def confirm(self, *args, **kwargs):
        self.calls += 1
        return TrustedApprovalDecision(True)


def _prepared(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("before\n", encoding="utf-8")
    staging_parent = tmp_path / "staging"
    staging_parent.mkdir()
    manager = WorkspaceManager(temp_root=staging_parent)
    handle = manager.prepare(source)
    stage_context = AuthorizationContext(
        run_id="security-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )
    stager = PatchStager(manager, handle, stage_context)
    source_context = AuthorizationContext(
        run_id="security-run",
        workspace_root=source,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity=repository_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )
    confirmer = _NeverConfirm()
    ledger = ApprovalLedger()
    service = PatchApprovalService(manager, handle, stager, source_context, confirmer, ledger)
    proposal = PatchProposal(
        replacements=(
            FileReplacement(
                path="module.py",
                operation="replace_text",
                expected_sha256=hashlib.sha256(b"before\n").hexdigest(),
                content="after\n",
            ),
        )
    )
    staged = stager.stage(proposal)
    assert staged.status is PatchStagingStatus.STAGED
    return source, manager, handle, confirmer, ledger, service, proposal, staged


def test_changed_source_file_invalidates_approval_before_confirmation(tmp_path: Path) -> None:
    source, manager, handle, confirmer, ledger, service, proposal, staged = _prepared(tmp_path)
    try:
        (source / "module.py").write_text("changed outside RepoPilot\n", encoding="utf-8")

        approval = service.request_approval(proposal, staged, operation_id="operation")

        assert not approval.approved
        assert approval.reason is ApprovalReasonCode.REPOSITORY_CHANGED
        assert confirmer.calls == 0
        assert (source / "module.py").read_text(encoding="utf-8") == "changed outside RepoPilot\n"
        assert ledger.audit_records[-1].reason is ApprovalReasonCode.REPOSITORY_CHANGED
        assert str(tmp_path) not in repr(ledger.audit_records)
        assert "changed outside RepoPilot" not in repr(ledger.audit_records)
    finally:
        manager.cleanup(handle)


def test_source_symlink_substitution_fails_before_confirmation(tmp_path: Path) -> None:
    source, manager, handle, confirmer, _, service, proposal, staged = _prepared(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("must stay unchanged\n", encoding="utf-8")
    try:
        (source / "module.py").unlink()
        (source / "module.py").symlink_to(outside)

        approval = service.request_approval(proposal, staged, operation_id="operation")

        assert not approval.approved
        assert approval.reason is ApprovalReasonCode.SCOPE_MISMATCH
        assert confirmer.calls == 0
        assert outside.read_text(encoding="utf-8") == "must stay unchanged\n"
    finally:
        manager.cleanup(handle)


def test_source_hardlink_substitution_fails_before_confirmation(tmp_path: Path) -> None:
    source, manager, handle, confirmer, _, service, proposal, staged = _prepared(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("before\n", encoding="utf-8")
    try:
        (source / "module.py").unlink()
        (source / "module.py").hardlink_to(outside)

        approval = service.request_approval(proposal, staged, operation_id="operation")

        assert not approval.approved
        assert approval.reason is ApprovalReasonCode.SCOPE_MISMATCH
        assert confirmer.calls == 0
        assert outside.read_text(encoding="utf-8") == "before\n"
    finally:
        manager.cleanup(handle)
