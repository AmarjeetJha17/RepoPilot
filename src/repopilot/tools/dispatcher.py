"""Freshly authorized dispatch for a fixed set of read-only repository tools."""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Event

from pydantic import BaseModel

from repopilot.agent.contracts import ToolCall
from repopilot.context import (
    IntelligenceError,
    RepositoryIntelligence,
)
from repopilot.context.models import (
    SearchResult,
    SymbolIndexResult,
    TextReadResult,
)
from repopilot.sandbox.workspace import (
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceHandle,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.security.capabilities import Capability
from repopilot.security.paths import (
    PathAuthorizationError,
    PathFailure,
    authorize_resource_path,
)
from repopilot.security.policy import (
    AuthorizationContext,
    ExecutionWorkspace,
    PolicyDecision,
    PolicyDecisionResult,
    PolicyEngine,
    PolicyReasonCode,
)
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.errors import ToolRegistryError, ToolRegistryErrorCode
from repopilot.tools.readonly import (
    DiscoverFilesArguments,
    IndexPythonArguments,
    ReadTextArguments,
    SearchLiteralArguments,
    readonly_tool_definitions,
)
from repopilot.tools.registry import ToolRegistry, ValidatedToolCall

MAX_DISPATCH_OUTPUT_BYTES = 32_768
MAX_DISPATCH_ITEMS = 100
MAX_DISPATCH_CALLS = 8
MAX_DISPATCH_SECONDS = 30.0
_SAFE_CALL_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class ToolExecutionStatus(StrEnum):
    """Safe final outcomes for a trusted dispatcher invocation."""

    SUCCESS = "success"
    VALIDATION_FAILURE = "validation_failure"
    POLICY_DENIED = "policy_denied"
    APPROVAL_REQUIRED = "approval_required"
    WORKSPACE_FAILURE = "workspace_failure"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    CANCELLED = "cancelled"
    EXECUTION_FAILURE = "execution_failure"


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Bounded structured result; payload JSON contains only actual handler output."""

    call_id: str | None
    tool_name: str | None
    status: ToolExecutionStatus
    executed: bool
    reason_code: str | None
    truncated: bool
    payload_size_bytes: int
    duration_ms: int
    payload_json: str | None = None


@dataclass(frozen=True, slots=True)
class ToolDispatchLimits:
    """Trusted per-dispatch caps; model arguments can only lower these ceilings."""

    max_output_bytes: int = 16_384
    max_result_items: int = 100
    max_calls: int = 8
    max_execution_seconds: float = 5.0

    def __post_init__(self) -> None:
        if (
            type(self.max_output_bytes) is not int
            or not 1 <= self.max_output_bytes <= MAX_DISPATCH_OUTPUT_BYTES
            or type(self.max_result_items) is not int
            or not 1 <= self.max_result_items <= MAX_DISPATCH_ITEMS
            or type(self.max_calls) is not int
            or not 1 <= self.max_calls <= MAX_DISPATCH_CALLS
            or isinstance(self.max_execution_seconds, bool)
            or not isinstance(self.max_execution_seconds, int | float)
            or not math.isfinite(self.max_execution_seconds)
            or not 0 < self.max_execution_seconds <= MAX_DISPATCH_SECONDS
        ):
            raise ValueError("Tool dispatch limits must be positive and within hard ceilings.")


class ReadOnlyToolDispatcher:
    """Validate, reauthorize, bind, and execute only the four fixed read operations."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        authorization: AuthorizationContext,
        manager: WorkspaceManager,
        handle: WorkspaceHandle,
        intelligence: RepositoryIntelligence,
        limits: ToolDispatchLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._registry = registry
        self._policy = policy_engine
        self._authorization = authorization
        self._manager = manager
        self._handle = handle
        self._intelligence = intelligence
        self._limits = limits or ToolDispatchLimits()
        self._monotonic = monotonic
        self._allowlist = {item.name: item for item in readonly_tool_definitions()}

    def dispatch(self, call: ToolCall, *, cancellation: Event | None = None) -> ToolExecutionResult:
        """Execute one proposal, returning a content-minimized outcome on failure."""
        started = self._monotonic()
        call_id, tool_name = _safe_call_metadata(call)
        if cancellation is not None and cancellation.is_set():
            return self._failure(
                call_id, tool_name, ToolExecutionStatus.CANCELLED, "cancelled", started
            )
        try:
            validated = self._registry.validate_call(call)
        except ToolRegistryError as error:
            return self._failure(
                call_id,
                tool_name,
                ToolExecutionStatus.VALIDATION_FAILURE,
                error.code.value,
                started,
            )
        if _SAFE_CALL_ID.fullmatch(validated.call_id) is None:
            return self._failure(
                None,
                validated.name,
                ToolExecutionStatus.VALIDATION_FAILURE,
                ToolRegistryErrorCode.INVALID_CALL_ID.value,
                started,
            )
        return self._execute_validated(validated, started, cancellation)

    def dispatch_batch(
        self, calls: Sequence[ToolCall], *, cancellation: Event | None = None
    ) -> tuple[ToolExecutionResult, ...]:
        """Validate a batch atomically; stop at the first failure, denial, or cancellation."""
        started = self._monotonic()
        if cancellation is not None and cancellation.is_set():
            return (self._failure(None, None, ToolExecutionStatus.CANCELLED, "cancelled", started),)
        if not isinstance(calls, Sequence) or isinstance(calls, str | bytes):
            return (
                self._failure(
                    None,
                    None,
                    ToolExecutionStatus.VALIDATION_FAILURE,
                    ToolRegistryErrorCode.INVALID_ARGUMENTS.value,
                    started,
                ),
            )
        if len(calls) > self._limits.max_calls:
            return (
                self._failure(
                    None,
                    None,
                    ToolExecutionStatus.VALIDATION_FAILURE,
                    "batch_too_large",
                    started,
                ),
            )
        try:
            validated_calls = self._registry.validate_calls(calls)
        except ToolRegistryError as error:
            return (
                self._failure(
                    None,
                    None,
                    ToolExecutionStatus.VALIDATION_FAILURE,
                    error.code.value,
                    started,
                ),
            )
        if any(_SAFE_CALL_ID.fullmatch(call.call_id) is None for call in validated_calls):
            return (
                self._failure(
                    None,
                    None,
                    ToolExecutionStatus.VALIDATION_FAILURE,
                    ToolRegistryErrorCode.INVALID_CALL_ID.value,
                    started,
                ),
            )
        results: list[ToolExecutionResult] = []
        for validated in validated_calls:
            result = self._execute_validated(validated, started, cancellation)
            results.append(result)
            if result.status is not ToolExecutionStatus.SUCCESS:
                break
        return tuple(results)

    def _execute_validated(
        self,
        call: ValidatedToolCall,
        started: float,
        cancellation: Event | None,
    ) -> ToolExecutionResult:
        if _SAFE_CALL_ID.fullmatch(call.call_id) is None:
            return self._failure(
                None,
                call.name if call.name in self._allowlist else None,
                ToolExecutionStatus.VALIDATION_FAILURE,
                ToolRegistryErrorCode.INVALID_CALL_ID.value,
                started,
            )
        definition = self._allowlist.get(call.name)
        if definition is None:
            return self._failure(
                call.call_id,
                None,
                ToolExecutionStatus.POLICY_DENIED,
                "not_allowlisted",
                started,
            )
        try:
            registered = self._registry.get(call.name)
        except ToolRegistryError:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                "allowlist_mismatch",
                started,
            )
        if registered != definition:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                "allowlist_mismatch",
                started,
            )
        try:
            self._verify_binding()
        except WorkspaceError:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.WORKSPACE_FAILURE,
                "workspace_binding_mismatch",
                started,
            )
        try:
            self._verify_scopes(definition, call.arguments)
            current = self._registry.validate_call(
                ToolCall(
                    call.call_id,
                    call.name,
                    call.arguments.model_dump(mode="python", by_alias=True),
                )
            )
        except PathAuthorizationError as error:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                _path_reason(error.failure),
                started,
            )
        except IntelligenceError as error:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                error.code.value,
                started,
            )
        except ToolRegistryError as error:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                error.code.value,
                started,
            )
        if current != call:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.VALIDATION_FAILURE,
                ToolRegistryErrorCode.INVALID_ARGUMENTS.value,
                started,
            )
        if cancellation is not None and cancellation.is_set():
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.CANCELLED,
                "cancelled",
                started,
            )
        if self._elapsed(started) >= self._limits.max_execution_seconds:
            # shortcut: blocking reads cannot be preempted; upgrade only with a bounded worker.
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.EXECUTION_FAILURE,
                "time_budget_exceeded",
                started,
            )
        try:
            policy_call = self._registry.validate_call(
                ToolCall(
                    current.call_id,
                    current.name,
                    current.arguments.model_dump(mode="python", by_alias=True),
                )
            )
            decision = self._policy.authorize(
                policy_call, self._authorization, self._handle.staging_root
            )
        except Exception:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                "policy_failure",
                started,
            )
        if not _policy_result_matches(
            decision, current, self._authorization, definition.capabilities
        ):
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                "invalid_policy_result",
                started,
            )
        if decision.decision is PolicyDecision.REQUIRE_APPROVAL:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.APPROVAL_REQUIRED,
                decision.reason_code.value,
                started,
            )
        if decision.decision is not PolicyDecision.ALLOW:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                decision.reason_code.value,
                started,
            )
        if cancellation is not None and cancellation.is_set():
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.CANCELLED,
                "cancelled",
                started,
            )
        try:
            self._verify_binding()
        except WorkspaceError:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.WORKSPACE_FAILURE,
                "workspace_binding_changed",
                started,
            )
        try:
            current = self._registry.validate_call(
                ToolCall(
                    current.call_id,
                    current.name,
                    current.arguments.model_dump(mode="python", by_alias=True),
                )
            )
            if current != policy_call or self._registry.get(current.name) != definition:
                raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS)
            self._verify_scopes(definition, current.arguments)
        except ToolRegistryError as error:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.VALIDATION_FAILURE,
                error.code.value,
                started,
            )
        except (PathAuthorizationError, IntelligenceError) as error:
            reason = (
                _path_reason(error.failure)
                if isinstance(error, PathAuthorizationError)
                else error.code.value
            )
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.POLICY_DENIED,
                reason,
                started,
            )
        if cancellation is not None and cancellation.is_set():
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.CANCELLED,
                "cancelled",
                started,
            )
        if self._elapsed(started) >= self._limits.max_execution_seconds:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.EXECUTION_FAILURE,
                "time_budget_exceeded",
                started,
            )
        try:
            payload, handler_truncated = self._invoke(current)
        except IntelligenceError as error:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.WORKSPACE_FAILURE,
                error.code.value,
                started,
                executed=True,
            )
        except WorkspaceError as error:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.WORKSPACE_FAILURE,
                error.code.value,
                started,
                executed=True,
            )
        except Exception:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.EXECUTION_FAILURE,
                "handler_failure",
                started,
                executed=True,
            )
        if cancellation is not None and cancellation.is_set():
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.CANCELLED,
                "cancelled_after_read",
                started,
                executed=True,
            )
        if self._elapsed(started) >= self._limits.max_execution_seconds:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.EXECUTION_FAILURE,
                "time_budget_exceeded",
                started,
                executed=True,
            )
        payload, item_truncated = _cap_payload_items(payload, self._limits.max_result_items)
        try:
            payload_json = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.EXECUTION_FAILURE,
                "invalid_handler_result",
                started,
                executed=True,
            )
        payload_size = len(payload_json.encode("utf-8"))
        if payload_size > self._limits.max_output_bytes:
            return self._failure(
                call.call_id,
                call.name,
                ToolExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
                "output_limit_exceeded",
                started,
                executed=True,
                truncated=True,
                payload_size_bytes=payload_size,
            )
        return ToolExecutionResult(
            call.call_id,
            call.name,
            ToolExecutionStatus.SUCCESS,
            True,
            None,
            handler_truncated or item_truncated,
            payload_size,
            self._duration_ms(started),
            payload_json,
        )

    def _verify_binding(self) -> None:
        if not isinstance(self._authorization, AuthorizationContext):
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        self._manager.read_access(self._handle)
        if not self._intelligence.is_bound_to(self._manager, self._handle):
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        try:
            actual_root = self._handle.staging_root.resolve(strict=True)
            authorized_root = self._authorization.workspace_root.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH) from error
        if (
            actual_root != authorized_root
            or self._authorization.workspace is not ExecutionWorkspace.STAGING
            or self._authorization.workspace_identity != workspace_identity_for_handle(self._handle)
        ):
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)

    def _verify_scopes(self, definition: ToolDefinition, arguments: BaseModel) -> None:
        if not definition.resource_fields:
            raise PathAuthorizationError(PathFailure.INVALID)
        for field in definition.resource_fields:
            value = getattr(arguments, field)
            values = value if isinstance(value, list | tuple) else (value,)
            if not values:
                raise PathAuthorizationError(PathFailure.INVALID)
            for resource in values:
                normalized = authorize_resource_path(
                    self._authorization.workspace_root,
                    resource,
                    resource_type=definition.resource_type,
                    sensitive_patterns=self._authorization.sensitive_resource_patterns,
                    allow_missing=False,
                    forbid_symlinks=True,
                )
                if normalized != resource:
                    raise PathAuthorizationError(PathFailure.INVALID)

    def _invoke(self, call: ValidatedToolCall) -> tuple[dict[str, object], bool]:
        arguments = call.arguments
        if call.name == "repo_discover_files" and isinstance(arguments, DiscoverFilesArguments):
            inventory = self._intelligence.discover_files(
                suffixes=arguments.suffixes,
                max_files=arguments.max_files,
                max_depth=arguments.max_depth,
                max_entries=arguments.max_entries,
            )
            files = [
                {"path": item.path, "size_bytes": item.size_bytes}
                for item in inventory.files
                if _visible_path(self._authorization, self._handle.staging_root, item.path)
            ]
            payload = {
                "entries_scanned": inventory.entries_scanned,
                "files": files,
                "truncated": inventory.truncated,
            }
            return payload, inventory.truncated
        if call.name == "repo_read_text" and isinstance(arguments, ReadTextArguments):
            text_result = self._intelligence.read_text(
                arguments.path,
                start_line=arguments.start_line,
                end_line=arguments.end_line,
                max_bytes=arguments.max_bytes,
                max_lines=arguments.max_lines,
                max_file_bytes=arguments.max_file_bytes,
            )
            return _text_payload(text_result), text_result.truncated
        if call.name == "repo_search_literal" and isinstance(arguments, SearchLiteralArguments):
            search_result = self._intelligence.search_literal(
                arguments.query,
                case_sensitive=arguments.case_sensitive,
                max_files=len(arguments.paths),
                max_bytes=arguments.max_bytes,
                max_matches=arguments.max_matches,
                paths=arguments.paths,
            )
            return _search_payload(search_result), search_result.truncated
        if call.name == "repo_index_python" and isinstance(arguments, IndexPythonArguments):
            index_result = self._intelligence.index_python(
                arguments.paths,
                max_files=len(arguments.paths),
                max_bytes=arguments.max_bytes,
                max_nodes=arguments.max_nodes,
                max_symbols=arguments.max_symbols,
            )
            return _index_payload(index_result), index_result.truncated
        raise ValueError("No trusted handler is registered for this tool.")

    def _elapsed(self, started: float) -> float:
        return max(0.0, self._monotonic() - started)

    def _duration_ms(self, started: float) -> int:
        return int(self._elapsed(started) * 1000)

    def _failure(
        self,
        call_id: str | None,
        tool_name: str | None,
        status: ToolExecutionStatus,
        reason: str,
        started: float,
        *,
        executed: bool = False,
        truncated: bool = False,
        payload_size_bytes: int = 0,
    ) -> ToolExecutionResult:
        return ToolExecutionResult(
            call_id,
            tool_name,
            status,
            executed,
            reason,
            truncated,
            payload_size_bytes,
            self._duration_ms(started),
        )


def _safe_call_metadata(call: object) -> tuple[str | None, str | None]:
    if not isinstance(call, ToolCall):
        return None, None
    call_id = call.id if isinstance(call.id, str) and _SAFE_CALL_ID.fullmatch(call.id) else None
    allowed_names = {definition.name for definition in readonly_tool_definitions()}
    tool_name = call.name if isinstance(call.name, str) and call.name in allowed_names else None
    return call_id, tool_name


def _policy_result_matches(
    decision: object,
    call: ValidatedToolCall,
    authorization: AuthorizationContext,
    capabilities: frozenset[Capability],
) -> bool:
    if not isinstance(decision, PolicyDecisionResult):
        return False
    if (
        decision.run_id != authorization.run_id
        or decision.call_id != call.call_id
        or not isinstance(decision.decision, PolicyDecision)
        or not isinstance(decision.reason_code, PolicyReasonCode)
    ):
        return False
    if decision.decision in {PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL}:
        return decision.capabilities == tuple(
            sorted(capabilities, key=lambda item: item.value)
        ) and (decision.decision is not PolicyDecision.ALLOW or decision.approval_request is None)
    return True


def _path_reason(failure: PathFailure) -> str:
    return {
        PathFailure.INVALID: PolicyReasonCode.INVALID_RESOURCE_PATH.value,
        PathFailure.OUTSIDE: PolicyReasonCode.RESOURCE_OUTSIDE_WORKSPACE.value,
        PathFailure.SENSITIVE: PolicyReasonCode.SENSITIVE_RESOURCE.value,
        PathFailure.TYPE_MISMATCH: PolicyReasonCode.RESOURCE_TYPE_MISMATCH.value,
        PathFailure.MISSING: PolicyReasonCode.RESOURCE_NOT_FOUND.value,
        PathFailure.SYMLINK: PolicyReasonCode.SYMLINK_NOT_ALLOWED.value,
    }[failure]


def _visible_path(context: AuthorizationContext, workspace: Path, path: str) -> bool:
    try:
        authorize_resource_path(
            workspace,
            path,
            resource_type="file",
            sensitive_patterns=context.sensitive_resource_patterns,
            allow_missing=False,
            forbid_symlinks=True,
        )
    except PathAuthorizationError:
        return False
    return True


def _text_payload(result: TextReadResult) -> dict[str, object]:
    return {
        "baseline_matches": result.baseline_matches,
        "end_line_exclusive": result.end_line_exclusive,
        "path": result.path,
        "sha256": result.sha256,
        "start_line": result.start_line,
        "text": result.text,
        "total_lines": result.total_lines,
        "truncated": result.truncated,
    }


def _search_payload(result: SearchResult) -> dict[str, object]:
    return {
        "bytes_scanned": result.bytes_scanned,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "matches": [
            {"column": item.column, "excerpt": item.excerpt, "line": item.line, "path": item.path}
            for item in result.matches
        ],
        "truncated": result.truncated,
    }


def _index_payload(result: SymbolIndexResult) -> dict[str, object]:
    return {
        "bytes_scanned": result.bytes_scanned,
        "files_scanned": result.files_scanned,
        "issues": [{"code": issue.code.value, "path": issue.path} for issue in result.issues],
        "symbols": [
            {
                "end_line": symbol.end_line,
                "kind": symbol.kind.value,
                "name": symbol.name,
                "path": symbol.path,
                "qualified_name": symbol.qualified_name,
                "start_line": symbol.start_line,
            }
            for symbol in result.symbols
        ],
        "truncated": result.truncated,
    }


def _cap_payload_items(
    payload: dict[str, object], max_items: int
) -> tuple[dict[str, object], bool]:
    bounded = dict(payload)
    truncated = False
    remaining = max_items
    for key, items in bounded.items():
        if not isinstance(items, list):
            continue
        included = min(len(items), remaining)
        if included < len(items):
            bounded[key] = items[:remaining]
            truncated = True
        remaining -= included
    if truncated:
        bounded["truncated"] = True
    return bounded, truncated
