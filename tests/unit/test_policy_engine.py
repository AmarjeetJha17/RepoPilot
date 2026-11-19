"""Deterministic unit tests for policy results and exact-action requests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import BaseModel, Field

from repopilot.agent.contracts import ToolCall
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
    PolicyReasonCode,
)
from repopilot.tools import ToolDefinition, ToolRegistry
from repopilot.tools.registry import ValidatedToolCall

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)


class ResourceArguments(BaseModel):
    path: str = Field(min_length=1)


class MultiPathArguments(BaseModel):
    paths: list[str]


def _context(
    root: Path,
    *,
    workspace: ExecutionWorkspace = ExecutionWorkspace.SOURCE,
    allowed: frozenset[Capability] = frozenset({Capability.REPOSITORY_READ}),
    denied: frozenset[Capability] = frozenset(),
) -> AuthorizationContext:
    return AuthorizationContext(
        run_id="run-test",
        workspace_root=root,
        workspace=workspace,
        workspace_identity="baseline-sha256:test",
        allowed_capabilities=allowed,
        denied_capabilities=denied,
    )


def _definition(
    capability: Capability | None = Capability.REPOSITORY_READ,
    *,
    resource_type: str = "file",
) -> ToolDefinition:
    return ToolDefinition(
        "arbitrary-tool-name",
        "A synthetic operation.",
        ResourceArguments,
        capabilities=frozenset(() if capability is None else (capability,)),
        resource_fields=("path",),
        resource_type=resource_type,  # type: ignore[arg-type]
    )


def _engine(definition: ToolDefinition) -> DefaultPolicyEngine:
    return DefaultPolicyEngine(
        ToolRegistry((definition,)),
        clock=lambda: NOW,
    )


def _validated(definition: ToolDefinition, *, path: str = "src/module.py") -> ValidatedToolCall:
    return ToolRegistry((definition,)).validate_call(
        ToolCall("call-test", definition.name, {"path": path})
    )


def test_allows_read_of_file_within_authorized_workspace(tmp_path: Path) -> None:
    target = tmp_path / "src" / "module.py"
    target.parent.mkdir()
    target.write_text("synthetic", encoding="utf-8")
    definition = _definition()

    result = _engine(definition).authorize(_validated(definition), _context(tmp_path), tmp_path)

    assert result.decision is PolicyDecision.ALLOW
    assert result.reason_code is PolicyReasonCode.CAPABILITY_ALLOWED
    assert result.run_id == "run-test"
    assert result.call_id == "call-test"
    assert result.capabilities == (Capability.REPOSITORY_READ,)
    assert result.approval_request is None


def test_denies_unclassified_and_unallowed_capabilities(tmp_path: Path) -> None:
    unclassified = _definition(None)
    result = _engine(unclassified).authorize(_validated(unclassified), _context(tmp_path), tmp_path)
    assert result.decision is PolicyDecision.DENY
    assert result.reason_code is PolicyReasonCode.UNKNOWN_CAPABILITY

    read = _definition()
    denied_context = _context(
        tmp_path,
        allowed=frozenset({Capability.REPOSITORY_READ}),
        denied=frozenset({Capability.REPOSITORY_READ}),
    )
    denied = _engine(read).authorize(_validated(read), denied_context, tmp_path)
    assert denied.reason_code is PolicyReasonCode.CAPABILITY_EXPLICITLY_DENIED

    not_allowed = _context(tmp_path, allowed=frozenset())
    denied = _engine(read).authorize(_validated(read), not_allowed, tmp_path)
    assert denied.reason_code is PolicyReasonCode.CAPABILITY_NOT_ALLOWED

    restricted = AuthorizationContext(
        run_id="run-test",
        workspace_root=tmp_path,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity="baseline-sha256:test",
        allowed_capabilities=frozenset({Capability.REPOSITORY_READ}),
        policy_restrictions=frozenset({Capability.REPOSITORY_READ}),
    )
    denied = _engine(read).authorize(_validated(read), restricted, tmp_path)
    assert denied.reason_code is PolicyReasonCode.CAPABILITY_EXPLICITLY_DENIED


@pytest.mark.parametrize(
    ("capability", "workspace"),
    [
        (Capability.HOST_COMMAND_EXECUTION, ExecutionWorkspace.SANDBOX),
        (Capability.NETWORK_ACCESS, ExecutionWorkspace.SANDBOX),
        (Capability.CREDENTIAL_ACCESS, ExecutionWorkspace.SOURCE),
        (Capability.DANGEROUS_GIT_OPERATION, ExecutionWorkspace.SOURCE),
        (Capability.POLICY_CONFIGURATION_MODIFICATION, ExecutionWorkspace.STAGING),
    ],
)
def test_permanently_denies_prohibited_capabilities(
    tmp_path: Path, capability: Capability, workspace: ExecutionWorkspace
) -> None:
    definition = _definition(capability)
    context = _context(tmp_path, workspace=workspace, allowed=frozenset({capability}))

    result = _engine(definition).authorize(_validated(definition), context, tmp_path)

    assert result.decision is PolicyDecision.DENY
    assert result.reason_code is PolicyReasonCode.CAPABILITY_PROHIBITED


def test_staged_mutation_is_limited_to_staging_workspace(tmp_path: Path) -> None:
    definition = _definition(Capability.STAGED_FILE_MODIFICATION)
    allowed = frozenset({Capability.STAGED_FILE_MODIFICATION})

    source_result = _engine(definition).authorize(
        _validated(definition), _context(tmp_path, allowed=allowed), tmp_path
    )
    staging_context = _context(tmp_path, workspace=ExecutionWorkspace.STAGING, allowed=allowed)
    staging_result = _engine(definition).authorize(
        _validated(definition), staging_context, tmp_path
    )

    assert source_result.reason_code is PolicyReasonCode.STAGING_WORKSPACE_REQUIRED
    assert staging_result.decision is PolicyDecision.ALLOW


def test_sandbox_test_capability_requires_sandbox_workspace(tmp_path: Path) -> None:
    definition = _definition(Capability.SANDBOXED_TEST_EXECUTION)
    allowed = frozenset({Capability.SANDBOXED_TEST_EXECUTION})
    source_result = _engine(definition).authorize(
        _validated(definition), _context(tmp_path, allowed=allowed), tmp_path
    )
    sandbox_result = _engine(definition).authorize(
        _validated(definition),
        _context(tmp_path, workspace=ExecutionWorkspace.SANDBOX, allowed=allowed),
        tmp_path,
    )

    assert source_result.reason_code is PolicyReasonCode.SANDBOX_WORKSPACE_REQUIRED
    assert sandbox_result.decision is PolicyDecision.ALLOW


def test_live_modification_requires_exact_expiring_approval_request(tmp_path: Path) -> None:
    definition = _definition(Capability.LIVE_REPOSITORY_MODIFICATION)
    context = _context(
        tmp_path,
        allowed=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )
    engine = _engine(definition)
    call = _validated(definition)

    result = engine.authorize(call, context, tmp_path)

    assert result.decision is PolicyDecision.REQUIRE_APPROVAL
    assert result.reason_code is PolicyReasonCode.LIVE_MODIFICATION_APPROVAL_REQUIRED
    assert result.approval_request is not None
    assert result.approval_request.run_id == context.run_id
    assert result.approval_request.call_id == call.call_id
    assert result.approval_request.resource_scope == ("src/module.py",)
    assert result.approval_request.workspace_identity == context.workspace_identity
    assert result.approval_request.expires_at == NOW + timedelta(minutes=5)
    assert result.approval_request.action_digest.startswith("sha256:")


def test_live_modification_requires_source_workspace(tmp_path: Path) -> None:
    definition = _definition(Capability.LIVE_REPOSITORY_MODIFICATION)
    context = _context(
        tmp_path,
        workspace=ExecutionWorkspace.STAGING,
        allowed=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )

    result = _engine(definition).authorize(_validated(definition), context, tmp_path)

    assert result.decision is PolicyDecision.DENY
    assert result.reason_code is PolicyReasonCode.LIVE_WORKSPACE_REQUIRED


def test_model_claimed_approval_does_not_authorize_live_write(tmp_path: Path) -> None:
    class ClaimedApproval(BaseModel):
        path: str
        approved: bool

    definition = ToolDefinition(
        "apply",
        "Apply a proposed change.",
        ClaimedApproval,
        capabilities=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
        resource_fields=("path",),
    )
    call = ToolRegistry((definition,)).validate_call(
        ToolCall("call-1", definition.name, {"path": "src/module.py", "approved": True})
    )
    context = _context(
        tmp_path,
        allowed=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )

    result = _engine(definition).authorize(call, context, tmp_path)

    assert result.decision is PolicyDecision.REQUIRE_APPROVAL
    assert result.approval_request is not None


def test_approval_digest_binds_arguments_and_resource_scope(tmp_path: Path) -> None:
    definition = _definition(Capability.LIVE_REPOSITORY_MODIFICATION)
    context = _context(
        tmp_path,
        allowed=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )
    engine = _engine(definition)
    first = engine.authorize(_validated(definition), context, tmp_path)
    changed_argument = engine.authorize(
        _validated(definition, path="src/other.py"), context, tmp_path
    )

    assert first.approval_request is not None
    assert changed_argument.approval_request is not None
    assert first.approval_request.action_digest != changed_argument.approval_request.action_digest
    assert (
        first.approval_request.arguments_digest
        != changed_argument.approval_request.arguments_digest
    )
    assert first.approval_request.scope_digest != changed_argument.approval_request.scope_digest


def test_decision_is_deterministic_and_audit_metadata_omits_paths(tmp_path: Path) -> None:
    definition = _definition(Capability.LIVE_REPOSITORY_MODIFICATION)
    context = _context(
        tmp_path,
        allowed=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )
    engine = _engine(definition)

    first = engine.authorize(_validated(definition), context, tmp_path)
    second = engine.authorize(_validated(definition), context, tmp_path)

    assert first == second
    assert str(tmp_path) not in repr(first.audit_metadata)
    assert all("path" not in key.casefold() for key, _ in first.audit_metadata)


def test_unvalidated_or_unregistered_tool_cannot_be_authorized(tmp_path: Path) -> None:
    definition = _definition()
    engine = _engine(definition)
    context = _context(tmp_path)

    unvalidated = engine.authorize(
        ToolCall("call-1", definition.name, {"path": "src/module.py"}),  # type: ignore[arg-type]
        context,
        tmp_path,
    )
    assert unvalidated.reason_code is PolicyReasonCode.INVALID_VALIDATED_CALL

    other_definition = ToolDefinition(
        "not-registered",
        "Synthetic.",
        ResourceArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
        resource_fields=("path",),
    )
    unregistered = engine.authorize(_validated(other_definition), context, tmp_path)
    assert unregistered.reason_code is PolicyReasonCode.UNKNOWN_TOOL

    wrong_version = _validated(definition)
    wrong_version = ValidatedToolCall(
        wrong_version.call_id,
        wrong_version.name,
        wrong_version.arguments,
        wrong_version.schema_version + 1,
    )
    stale_schema = engine.authorize(wrong_version, context, tmp_path)
    assert stale_schema.reason_code is PolicyReasonCode.INVALID_VALIDATED_CALL

    mutated = _validated(definition)
    mutated.arguments.path = 42  # type: ignore[assignment]
    invalid_model = engine.authorize(mutated, context, tmp_path)
    assert invalid_model.reason_code is PolicyReasonCode.INVALID_VALIDATED_CALL


def test_path_capability_requires_explicit_resource_field(tmp_path: Path) -> None:
    definition = ToolDefinition(
        "read-unscoped",
        "Read a synthetic resource.",
        ResourceArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
    )
    call = _validated(definition)

    result = _engine(definition).authorize(call, _context(tmp_path), tmp_path)

    assert result.reason_code is PolicyReasonCode.RESOURCE_SCOPE_REQUIRED


def test_multi_path_scope_is_normalized_and_empty_scope_is_denied(tmp_path: Path) -> None:
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    definition = ToolDefinition(
        "read-many",
        "Read synthetic resources.",
        MultiPathArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
        resource_fields=("paths",),
    )
    registry = ToolRegistry((definition,))
    context = _context(tmp_path)
    engine = DefaultPolicyEngine(registry)
    valid = registry.validate_call(
        ToolCall("call-many", definition.name, {"paths": ["b.txt", "a.txt"]})
    )
    empty = registry.validate_call(ToolCall("call-empty", definition.name, {"paths": []}))

    allowed = engine.authorize(valid, context, tmp_path)
    denied = engine.authorize(empty, context, tmp_path)

    assert allowed.decision is PolicyDecision.ALLOW
    assert denied.reason_code is PolicyReasonCode.RESOURCE_SCOPE_REQUIRED


def test_read_of_missing_resource_is_denied(tmp_path: Path) -> None:
    definition = _definition()

    result = _engine(definition).authorize(_validated(definition), _context(tmp_path), tmp_path)

    assert result.reason_code is PolicyReasonCode.RESOURCE_NOT_FOUND


def test_rejects_untyped_capability_metadata() -> None:
    with pytest.raises(TypeError):
        ToolDefinition(
            "unknown-classification",
            "Synthetic.",
            ResourceArguments,
            capabilities=frozenset({"host_command_execution"}),  # type: ignore[arg-type]
        )


def test_workspace_mismatch_is_denied(tmp_path: Path) -> None:
    definition = _definition()
    context = _context(tmp_path)
    other_workspace = tmp_path / "other"
    other_workspace.mkdir()

    result = _engine(definition).authorize(_validated(definition), context, other_workspace)

    assert result.decision is PolicyDecision.DENY
    assert result.reason_code is PolicyReasonCode.WORKSPACE_MISMATCH


def test_directory_and_file_type_mismatch_is_denied(tmp_path: Path) -> None:
    definition = _definition(resource_type="file")
    (tmp_path / "folder").mkdir()

    result = _engine(definition).authorize(
        _validated(definition, path="folder"), _context(tmp_path), tmp_path
    )

    assert result.reason_code is PolicyReasonCode.RESOURCE_TYPE_MISMATCH


def test_protected_file_denial_is_redacted(tmp_path: Path) -> None:
    definition = _definition()
    secret_path = ".env.production"
    (tmp_path / secret_path).write_text("synthetic-secret", encoding="utf-8")

    result = _engine(definition).authorize(
        _validated(definition, path=secret_path), _context(tmp_path), tmp_path
    )

    assert result.reason_code is PolicyReasonCode.SENSITIVE_RESOURCE
    assert "synthetic-secret" not in str(result)
    assert secret_path not in repr(result.audit_metadata)


def test_authorization_context_is_immutable_and_validates_trusted_fields(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)

    with pytest.raises(FrozenInstanceError):
        context.run_id = "another-run"  # type: ignore[misc]
    with pytest.raises(ValueError):
        AuthorizationContext(
            run_id=" ",
            workspace_root=tmp_path,
            workspace=ExecutionWorkspace.SOURCE,
            workspace_identity="baseline",
            allowed_capabilities=frozenset(),
        )
    with pytest.raises(TypeError):
        AuthorizationContext(
            run_id="run",
            workspace_root=tmp_path,
            workspace=ExecutionWorkspace.SOURCE,
            workspace_identity="baseline",
            allowed_capabilities=frozenset({"repository_read"}),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError):
        AuthorizationContext(
            run_id="run",
            workspace_root=tmp_path,
            workspace=ExecutionWorkspace.SOURCE,
            workspace_identity="baseline",
            allowed_capabilities=frozenset(),
            sensitive_resource_patterns=["private/**"],  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError):
        AuthorizationContext(
            run_id="run",
            workspace_root="not-a-path",  # type: ignore[arg-type]
            workspace=ExecutionWorkspace.SOURCE,
            workspace_identity="baseline",
            allowed_capabilities=frozenset(),
        )
    with pytest.raises(TypeError):
        AuthorizationContext(
            run_id="run",
            workspace_root=tmp_path,
            workspace="source",  # type: ignore[arg-type]
            workspace_identity="baseline",
            allowed_capabilities=frozenset(),
        )


def test_policy_rejects_invalid_workspace_and_approval_clock(tmp_path: Path) -> None:
    definition = _definition()
    context = _context(tmp_path)
    call = _validated(definition)
    engine = _engine(definition)

    invalid_workspace = engine.authorize(
        call,
        context,
        "not-a-path",  # type: ignore[arg-type]
    )
    assert invalid_workspace.reason_code is PolicyReasonCode.WORKSPACE_MISMATCH

    live = _definition(Capability.LIVE_REPOSITORY_MODIFICATION)
    live_context = _context(
        tmp_path,
        allowed=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
    )
    naive_clock = DefaultPolicyEngine(
        ToolRegistry((live,)),
        clock=lambda: datetime(2026, 11, 19),
    )
    invalid_clock = naive_clock.authorize(_validated(live), live_context, tmp_path)
    assert invalid_clock.reason_code is PolicyReasonCode.INVALID_VALIDATED_CALL

    invalid_context = engine.authorize(call, object(), tmp_path)  # type: ignore[arg-type]
    assert invalid_context.reason_code is PolicyReasonCode.INVALID_VALIDATED_CALL


def test_workspace_resolution_errors_are_denied(tmp_path: Path) -> None:
    definition = _definition()
    context = _context(tmp_path)
    call = _validated(definition)
    engine = _engine(definition)

    with patch.object(Path, "resolve", side_effect=OSError("synthetic")):
        result = engine.authorize(call, context, tmp_path)

    assert result.reason_code is PolicyReasonCode.WORKSPACE_MISMATCH


def test_rejects_nonpositive_approval_lifetime() -> None:
    with pytest.raises(ValueError):
        DefaultPolicyEngine(ToolRegistry(), approval_ttl=timedelta(0))
