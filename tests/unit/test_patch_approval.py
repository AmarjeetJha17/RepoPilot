"""Unit tests for trusted confirmation presentation and disabled application."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import StringIO

import pytest
from rich.console import Console

from repopilot.application.patch_approval import (
    LivePatchApplicationService,
    _approval_reason_for_policy_denial,
)
from repopilot.security.approval import (
    ApprovalConsumptionState,
    ApprovalLedger,
    ApprovalReasonCode,
    PatchManifestEntry,
    ReviewedPatchManifest,
)
from repopilot.security.policy import PolicyReasonCode
from repopilot.ui.approval import RichTerminalApproval

pytestmark = pytest.mark.unit


def _manifest() -> ReviewedPatchManifest:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    return ReviewedPatchManifest(
        run_id="run",
        operation_id="operation",
        repository_identity=f"sha256:{'a' * 64}",
        staging_workspace_identity="workspace:test",
        entries=(PatchManifestEntry("src/app.py", "b" * 64, "c" * 64),),
        diff_digest=f"sha256:{'d' * 64}",
        limits=(20, 1_000_000, 4_000_000, 20_000, 1_000_000, 20_000),
        created_at=created,
        expires_at=created + timedelta(minutes=2),
    )


@pytest.mark.parametrize(
    "reason",
    [
        PolicyReasonCode.INVALID_RESOURCE_PATH,
        PolicyReasonCode.RESOURCE_OUTSIDE_WORKSPACE,
        PolicyReasonCode.SENSITIVE_RESOURCE,
        PolicyReasonCode.RESOURCE_TYPE_MISMATCH,
        PolicyReasonCode.RESOURCE_NOT_FOUND,
        PolicyReasonCode.SYMLINK_NOT_ALLOWED,
    ],
)
def test_resource_path_denials_map_to_scope_mismatch(reason: PolicyReasonCode) -> None:
    assert _approval_reason_for_policy_denial(reason) is ApprovalReasonCode.SCOPE_MISMATCH


@pytest.mark.parametrize(
    "reason",
    [
        PolicyReasonCode.CAPABILITY_NOT_ALLOWED,
        PolicyReasonCode.CAPABILITY_EXPLICITLY_DENIED,
        PolicyReasonCode.UNKNOWN_TOOL,
        PolicyReasonCode.INVALID_VALIDATED_CALL,
        PolicyReasonCode.RESOURCE_SCOPE_REQUIRED,
        PolicyReasonCode.WORKSPACE_MISMATCH,
    ],
)
def test_capability_and_other_policy_denials_stay_generic(reason: PolicyReasonCode) -> None:
    assert _approval_reason_for_policy_denial(reason) is ApprovalReasonCode.POLICY_DENIED


def test_terminal_confirmation_defaults_to_denial_when_noninteractive() -> None:
    approval = RichTerminalApproval(
        console=Console(file=StringIO(), force_terminal=False),
        input_isatty=lambda: False,
    )

    result = approval.confirm(
        _manifest(), "safe diff", truncated=False, repository_label="synthetic"
    )

    assert not result.approved
    assert result.reason is ApprovalReasonCode.NONINTERACTIVE


def test_terminal_confirmation_refuses_truncated_preview_even_when_interactive() -> None:
    approval = RichTerminalApproval(
        console=Console(file=StringIO(), force_terminal=True),
        input_isatty=lambda: True,
    )

    result = approval.confirm(
        _manifest(), "partial diff", truncated=True, repository_label="synthetic"
    )

    assert not result.approved
    assert result.reason is ApprovalReasonCode.PREVIEW_TRUNCATED


def test_terminal_confirmation_accepts_explicit_local_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    output = StringIO()
    approval = RichTerminalApproval(
        console=Console(file=output, force_terminal=True),
        input_isatty=lambda: True,
    )
    monkeypatch.setattr("repopilot.ui.approval.Prompt.ask", lambda *args, **kwargs: "y")

    result = approval.confirm(
        _manifest(), "\x1b[31mvisible diff", truncated=False, repository_label="synthetic"
    )

    assert result.approved
    assert result.reason is None
    assert "src/app.py" in output.getvalue()
    assert "\\x1b[31mvisible diff" in output.getvalue()


def test_terminal_confirmation_rejects_explicit_no(monkeypatch: pytest.MonkeyPatch) -> None:
    approval = RichTerminalApproval(
        console=Console(file=StringIO(), force_terminal=True),
        input_isatty=lambda: True,
    )
    monkeypatch.setattr("repopilot.ui.approval.Prompt.ask", lambda *args, **kwargs: "N")

    result = approval.confirm(
        _manifest(), "complete diff", truncated=False, repository_label="synthetic"
    )

    assert not result.approved
    assert result.reason is ApprovalReasonCode.USER_DENIED


def test_disabled_application_consumes_receipt_without_source_access() -> None:
    manifest = _manifest()
    ledger = ApprovalLedger()
    receipt = ledger._issue(manifest, manifest.created_at)
    service = LivePatchApplicationService(ledger)

    result = service.apply(receipt, manifest, now=manifest.created_at)
    replay = service.apply(receipt, manifest, now=manifest.created_at)

    assert not result.applied
    assert result.reason is ApprovalReasonCode.LIVE_APPLICATION_DISABLED
    assert result.consumption.state is ApprovalConsumptionState.CONSUMED
    assert result.applied_paths == ()
    assert replay.reason is ApprovalReasonCode.REPLAYED
