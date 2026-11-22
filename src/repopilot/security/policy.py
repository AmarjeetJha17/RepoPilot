"""Deterministic authorization decisions, separate from validation and execution."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ValidationError

from repopilot.security.capabilities import Capability
from repopilot.security.paths import (
    DEFAULT_SENSITIVE_PATTERNS,
    PathAuthorizationError,
    PathFailure,
    authorize_resource_path,
)
from repopilot.tools import ToolRegistry, ToolRegistryError
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.registry import ValidatedToolCall


class PolicyDecision(StrEnum):
    """Possible outcomes from a deterministic authorization check."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "approval"
    REQUIRES_APPROVAL = "approval"


class ExecutionWorkspace(StrEnum):
    """Trusted classification of the workspace an operation would affect."""

    SOURCE = "source"
    STAGING = "staging"
    SANDBOX = "sandbox"


class PolicyReasonCode(StrEnum):
    """Stable, redactable reasons suitable for audit metadata."""

    CAPABILITY_ALLOWED = "capability_allowed"
    UNKNOWN_CAPABILITY = "unknown_capability"
    CAPABILITY_EXPLICITLY_DENIED = "capability_explicitly_denied"
    CAPABILITY_NOT_ALLOWED = "capability_not_allowed"
    CAPABILITY_PROHIBITED = "capability_prohibited"
    INVALID_VALIDATED_CALL = "invalid_validated_call"
    UNKNOWN_TOOL = "unknown_tool"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    STAGING_WORKSPACE_REQUIRED = "staging_workspace_required"
    SANDBOX_WORKSPACE_REQUIRED = "sandbox_workspace_required"
    LIVE_WORKSPACE_REQUIRED = "live_workspace_required"
    RESOURCE_SCOPE_REQUIRED = "resource_scope_required"
    INVALID_RESOURCE_PATH = "invalid_resource_path"
    RESOURCE_OUTSIDE_WORKSPACE = "resource_outside_workspace"
    SENSITIVE_RESOURCE = "sensitive_resource"
    RESOURCE_TYPE_MISMATCH = "resource_type_mismatch"
    RESOURCE_NOT_FOUND = "resource_not_found"
    SYMLINK_NOT_ALLOWED = "symlink_not_allowed"
    LIVE_MODIFICATION_APPROVAL_REQUIRED = "live_modification_approval_required"


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Trusted app-supplied scope; model output cannot expand these values."""

    run_id: str
    workspace_root: Path
    workspace: ExecutionWorkspace
    workspace_identity: str
    allowed_capabilities: frozenset[Capability]
    denied_capabilities: frozenset[Capability] = frozenset()
    sensitive_resource_patterns: tuple[str, ...] = DEFAULT_SENSITIVE_PATTERNS
    policy_restrictions: frozenset[Capability] = frozenset()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not self.run_id.strip()
            or not isinstance(self.workspace_identity, str)
            or not self.workspace_identity.strip()
        ):
            raise ValueError("Run and workspace identities must be non-empty.")
        if not isinstance(self.workspace_root, Path):
            raise TypeError("Authorized workspace root must be a Path.")
        if not isinstance(self.workspace, ExecutionWorkspace):
            raise TypeError("Workspace classification must be an ExecutionWorkspace.")
        for capabilities in (
            self.allowed_capabilities,
            self.denied_capabilities,
            self.policy_restrictions,
        ):
            if not isinstance(capabilities, frozenset) or any(
                not isinstance(capability, Capability) for capability in capabilities
            ):
                raise TypeError("Authorization capabilities must be known Capability values.")
        if not isinstance(self.sensitive_resource_patterns, tuple) or any(
            not isinstance(pattern, str) or not pattern
            for pattern in self.sensitive_resource_patterns
        ):
            raise TypeError("Sensitive-resource patterns must be a tuple of non-empty strings.")


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Exact-action approval request; it is neither consent nor an execution token."""

    run_id: str
    call_id: str
    arguments_digest: str
    resource_scope: tuple[str, ...]
    scope_digest: str
    workspace_identity: str
    action_digest: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyDecisionResult:
    """One structured decision with safe metadata and optional approval request."""

    decision: PolicyDecision
    reason_code: PolicyReasonCode
    run_id: str
    call_id: str
    capabilities: tuple[Capability, ...]
    audit_metadata: tuple[tuple[str, str], ...] = ()
    approval_request: ApprovalRequest | None = None


class PolicyEngine(Protocol):
    """Authorize a registry-validated call against a trusted context and workspace."""

    def authorize(
        self,
        call: ValidatedToolCall,
        context: AuthorizationContext,
        workspace: Path,
    ) -> PolicyDecisionResult:
        """Return a decision record; this contract never executes the call."""
        ...


_PERMANENTLY_DENIED = frozenset(
    {
        Capability.HOST_COMMAND_EXECUTION,
        Capability.NETWORK_ACCESS,
        Capability.CREDENTIAL_ACCESS,
        Capability.DANGEROUS_GIT_OPERATION,
        Capability.POLICY_CONFIGURATION_MODIFICATION,
    }
)
_PATH_SCOPED = frozenset(
    {
        Capability.REPOSITORY_READ,
        Capability.REPOSITORY_SEARCH,
        Capability.STAGED_FILE_MODIFICATION,
        Capability.LIVE_REPOSITORY_MODIFICATION,
        Capability.SANDBOXED_TEST_EXECUTION,
    }
)
_LIVE = Capability.LIVE_REPOSITORY_MODIFICATION
_STAGED = Capability.STAGED_FILE_MODIFICATION
_SANDBOXED_TEST = Capability.SANDBOXED_TEST_EXECUTION


class DefaultPolicyEngine:
    """Default-deny engine using only trusted registry metadata and app context."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        approval_ttl: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if approval_ttl <= timedelta(0):
            raise ValueError("Approval request lifetime must be positive.")
        self._registry = registry
        self._approval_ttl = approval_ttl
        self._clock = clock or (lambda: datetime.now(UTC))

    def authorize(
        self,
        call: ValidatedToolCall,
        context: AuthorizationContext,
        workspace: Path,
    ) -> PolicyDecisionResult:
        """Check a validated proposal without creating an executable permission token."""
        call_id = _safe_call_id(call)
        if not isinstance(context, AuthorizationContext):
            return _result(
                PolicyDecision.DENY,
                PolicyReasonCode.INVALID_VALIDATED_CALL,
                "unknown",
                call_id,
            )
        if not isinstance(call, ValidatedToolCall) or not call_id:
            return _result(
                PolicyDecision.DENY,
                PolicyReasonCode.INVALID_VALIDATED_CALL,
                context.run_id,
                call_id,
            )
        try:
            definition = self._registry.get(call.name)
        except ToolRegistryError:
            return _result(
                PolicyDecision.DENY,
                PolicyReasonCode.UNKNOWN_TOOL,
                context.run_id,
                call_id,
                tool="unknown",
            )
        if (
            call.name != definition.name
            or type(call.arguments) is not definition.arguments_model
            or call.schema_version != definition.schema_version
        ):
            return _result(
                PolicyDecision.DENY,
                PolicyReasonCode.INVALID_VALIDATED_CALL,
                context.run_id,
                call_id,
                tool=definition.name,
            )
        try:
            arguments = definition.arguments_model.model_validate(
                call.arguments.model_dump(
                    mode="python",
                    by_alias=True,
                    exclude_computed_fields=True,
                    warnings=False,
                ),
                strict=True,
                extra="forbid",
            )
        except (ValidationError, TypeError, ValueError):
            return _result(
                PolicyDecision.DENY,
                PolicyReasonCode.INVALID_VALIDATED_CALL,
                context.run_id,
                call_id,
                tool=definition.name,
            )
        call = ValidatedToolCall(call.call_id, call.name, arguments, call.schema_version)
        capabilities = tuple(sorted(definition.capabilities, key=lambda item: item.value))
        if not capabilities:
            return _result(
                PolicyDecision.DENY,
                PolicyReasonCode.UNKNOWN_CAPABILITY,
                context.run_id,
                call_id,
                tool=definition.name,
            )
        workspace_error = _check_workspace(workspace, context.workspace_root)
        if workspace_error is not None:
            return _result(
                PolicyDecision.DENY,
                workspace_error,
                context.run_id,
                call_id,
                capabilities,
                tool=definition.name,
                workspace=context.workspace,
            )

        scopes: set[str] = set()
        for capability in capabilities:
            failure = _capability_failure(capability, context)
            if failure is None:
                failure = _workspace_failure(capability, context.workspace)
            if failure is not None:
                return _result(
                    PolicyDecision.DENY,
                    failure,
                    context.run_id,
                    call_id,
                    capabilities,
                    tool=definition.name,
                    workspace=context.workspace,
                )
            if capability in _PATH_SCOPED:
                try:
                    scopes.update(_resource_scopes(definition, call.arguments, context, capability))
                except PathAuthorizationError as error:
                    return _result(
                        PolicyDecision.DENY,
                        _path_reason(error.failure),
                        context.run_id,
                        call_id,
                        capabilities,
                        tool=definition.name,
                        workspace=context.workspace,
                    )
                except (AttributeError, TypeError, ValueError):
                    return _result(
                        PolicyDecision.DENY,
                        PolicyReasonCode.RESOURCE_SCOPE_REQUIRED,
                        context.run_id,
                        call_id,
                        capabilities,
                        tool=definition.name,
                        workspace=context.workspace,
                    )

        canonical_scope = tuple(sorted(scopes))
        metadata = _audit_metadata(definition.name, context.workspace, canonical_scope)
        if _LIVE in capabilities:
            try:
                request = _approval_request(
                    call,
                    context,
                    capabilities,
                    canonical_scope,
                    self._clock(),
                    self._approval_ttl,
                )
            except (TypeError, ValueError, OverflowError):
                return _result(
                    PolicyDecision.DENY,
                    PolicyReasonCode.INVALID_VALIDATED_CALL,
                    context.run_id,
                    call_id,
                    capabilities,
                    tool=definition.name,
                    workspace=context.workspace,
                )
            return PolicyDecisionResult(
                PolicyDecision.REQUIRE_APPROVAL,
                PolicyReasonCode.LIVE_MODIFICATION_APPROVAL_REQUIRED,
                context.run_id,
                call_id,
                capabilities,
                metadata,
                request,
            )
        return PolicyDecisionResult(
            PolicyDecision.ALLOW,
            PolicyReasonCode.CAPABILITY_ALLOWED,
            context.run_id,
            call_id,
            capabilities,
            metadata,
        )


def _safe_call_id(call: object) -> str:
    if (
        isinstance(call, ValidatedToolCall)
        and isinstance(call.call_id, str)
        and 0 < len(call.call_id) <= 128
        and call.call_id.isprintable()
    ):
        return call.call_id
    return "invalid"


def _check_workspace(workspace: Path, authorized_root: Path) -> PolicyReasonCode | None:
    if not isinstance(workspace, Path) or not isinstance(authorized_root, Path):
        return PolicyReasonCode.WORKSPACE_MISMATCH
    try:
        actual = workspace.resolve(strict=True)
        expected = authorized_root.resolve(strict=True)
        if not actual.is_dir() or actual != expected:
            return PolicyReasonCode.WORKSPACE_MISMATCH
    except (OSError, RuntimeError, ValueError):
        return PolicyReasonCode.WORKSPACE_MISMATCH
    return None


def _capability_failure(
    capability: Capability, context: AuthorizationContext
) -> PolicyReasonCode | None:
    if not isinstance(capability, Capability):
        return PolicyReasonCode.UNKNOWN_CAPABILITY
    if capability in _PERMANENTLY_DENIED:
        return PolicyReasonCode.CAPABILITY_PROHIBITED
    if capability in context.denied_capabilities or capability in context.policy_restrictions:
        return PolicyReasonCode.CAPABILITY_EXPLICITLY_DENIED
    if capability not in context.allowed_capabilities:
        return PolicyReasonCode.CAPABILITY_NOT_ALLOWED
    return None


def _workspace_failure(
    capability: Capability, workspace: ExecutionWorkspace
) -> PolicyReasonCode | None:
    if capability is _STAGED and workspace is not ExecutionWorkspace.STAGING:
        return PolicyReasonCode.STAGING_WORKSPACE_REQUIRED
    if capability is _SANDBOXED_TEST and workspace is not ExecutionWorkspace.SANDBOX:
        return PolicyReasonCode.SANDBOX_WORKSPACE_REQUIRED
    if capability is _LIVE and workspace is not ExecutionWorkspace.SOURCE:
        return PolicyReasonCode.LIVE_WORKSPACE_REQUIRED
    return None


def _resource_scopes(
    definition: ToolDefinition,
    arguments: BaseModel,
    context: AuthorizationContext,
    capability: Capability,
) -> tuple[str, ...]:
    fields = definition.resource_fields
    if not fields:
        raise ValueError("Resource-scoped capability has no declared resource fields.")
    allow_missing = capability in {_STAGED, _LIVE}
    forbid_symlinks = capability in {_STAGED, _LIVE, _SANDBOXED_TEST}
    scopes: list[str] = []
    for field_name in fields:
        value = getattr(arguments, field_name)
        values: Sequence[object] = value if isinstance(value, list | tuple) else (value,)
        if not values:
            raise ValueError("Resource scope cannot be empty.")
        for item in values:
            scopes.append(
                authorize_resource_path(
                    context.workspace_root,
                    item,
                    resource_type=definition.resource_type,
                    sensitive_patterns=(
                        *DEFAULT_SENSITIVE_PATTERNS,
                        *context.sensitive_resource_patterns,
                    ),
                    allow_missing=allow_missing,
                    forbid_symlinks=forbid_symlinks,
                )
            )
    return tuple(scopes)


def _path_reason(failure: PathFailure) -> PolicyReasonCode:
    return {
        PathFailure.INVALID: PolicyReasonCode.INVALID_RESOURCE_PATH,
        PathFailure.OUTSIDE: PolicyReasonCode.RESOURCE_OUTSIDE_WORKSPACE,
        PathFailure.SENSITIVE: PolicyReasonCode.SENSITIVE_RESOURCE,
        PathFailure.TYPE_MISMATCH: PolicyReasonCode.RESOURCE_TYPE_MISMATCH,
        PathFailure.MISSING: PolicyReasonCode.RESOURCE_NOT_FOUND,
        PathFailure.SYMLINK: PolicyReasonCode.SYMLINK_NOT_ALLOWED,
    }[failure]


def _audit_metadata(
    tool_name: str, workspace: ExecutionWorkspace, scopes: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    digest = _digest(scopes)
    return (("tool", tool_name), ("workspace", workspace.value), ("scope_digest", digest))


def _approval_request(
    call: ValidatedToolCall,
    context: AuthorizationContext,
    capabilities: tuple[Capability, ...],
    scopes: tuple[str, ...],
    now: datetime,
    ttl: timedelta,
) -> ApprovalRequest:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Approval request clock must be timezone-aware.")
    expires_at = now.astimezone(UTC) + ttl
    arguments = call.arguments.model_dump(mode="json", by_alias=True)
    arguments_digest = _digest(arguments)
    scope_digest = _digest(scopes)
    action_digest = _digest(
        {
            "run_id": context.run_id,
            "call_id": call.call_id,
            "tool_name": call.name,
            "schema_version": call.schema_version,
            "capabilities": [capability.value for capability in capabilities],
            "arguments_digest": arguments_digest,
            "resource_scope": scopes,
            "workspace": context.workspace.value,
            "workspace_identity": context.workspace_identity,
            "expires_at": expires_at.isoformat(),
        }
    )
    return ApprovalRequest(
        run_id=context.run_id,
        call_id=call.call_id,
        arguments_digest=arguments_digest,
        resource_scope=scopes,
        scope_digest=scope_digest,
        workspace_identity=context.workspace_identity,
        action_digest=action_digest,
        expires_at=expires_at,
    )


def _digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _result(
    decision: PolicyDecision,
    reason: PolicyReasonCode,
    run_id: str,
    call_id: str,
    capabilities: tuple[Capability, ...] = (),
    *,
    tool: str = "unknown",
    workspace: ExecutionWorkspace | None = None,
) -> PolicyDecisionResult:
    metadata = [("tool", tool)]
    if workspace is not None:
        metadata.append(("workspace", workspace.value))
    return PolicyDecisionResult(decision, reason, run_id, call_id, capabilities, tuple(metadata))
