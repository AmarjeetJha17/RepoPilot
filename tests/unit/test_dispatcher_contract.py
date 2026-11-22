"""Portable validation and fixed-allowlist contracts for the read-only dispatcher."""

from __future__ import annotations

from threading import Event

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.security.capabilities import Capability
from repopilot.security.paths import PathAuthorizationError, PathFailure
from repopilot.security.policy import PolicyReasonCode
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.dispatcher import (
    ReadOnlyToolDispatcher,
    ToolDispatchLimits,
    ToolExecutionStatus,
    _cap_payload_items,
)
from repopilot.tools.readonly import create_readonly_tool_registry
from repopilot.tools.registry import ToolRegistry

pytestmark = pytest.mark.unit


class _NoPolicyCalls:
    def authorize(self, *_args: object) -> object:
        raise AssertionError("Policy must not run for pre-dispatch failures.")


def _dispatcher(registry: ToolRegistry | None = None) -> ReadOnlyToolDispatcher:
    return ReadOnlyToolDispatcher(
        registry=registry or create_readonly_tool_registry(),
        policy_engine=_NoPolicyCalls(),  # type: ignore[arg-type]
        authorization=None,  # type: ignore[arg-type]
        manager=None,  # type: ignore[arg-type]
        handle=None,  # type: ignore[arg-type]
        intelligence=None,  # type: ignore[arg-type]
    )


def test_unknown_tool_and_invalid_arguments_return_validation_failures() -> None:
    dispatcher = _dispatcher()

    unknown = dispatcher.dispatch(ToolCall("u1", "run_shell", {}))
    invalid = dispatcher.dispatch(
        ToolCall("r1", "repo_read_text", {"path": "x.py", "max_bytes": "large"})
    )

    assert unknown.status is ToolExecutionStatus.VALIDATION_FAILURE
    assert unknown.reason_code == "unknown_tool"
    assert not unknown.executed
    assert invalid.status is ToolExecutionStatus.VALIDATION_FAILURE
    assert invalid.reason_code == "invalid_arguments"
    assert not invalid.executed


def test_cancellation_prevents_registry_dispatch_without_policy_or_handler() -> None:
    dispatcher = _dispatcher()
    cancellation = Event()
    cancellation.set()

    result = dispatcher.dispatch(
        ToolCall("r2", "repo_read_text", {"path": "x.py"}), cancellation=cancellation
    )

    assert result.status is ToolExecutionStatus.CANCELLED
    assert not result.executed


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (PathFailure.SENSITIVE, PolicyReasonCode.SENSITIVE_RESOURCE.value),
        (PathFailure.INVALID, PolicyReasonCode.INVALID_RESOURCE_PATH.value),
        (PathFailure.SYMLINK, PolicyReasonCode.SYMLINK_NOT_ALLOWED.value),
    ],
)
def test_initial_scope_failure_returns_safe_path_reason(
    monkeypatch, failure: PathFailure, reason: str
) -> None:
    dispatcher = _dispatcher()
    monkeypatch.setattr(dispatcher, "_verify_binding", lambda: None)

    def reject_scope(*_args: object, **_kwargs: object) -> None:
        raise PathAuthorizationError(failure)

    monkeypatch.setattr(dispatcher, "_verify_scopes", reject_scope)
    result = dispatcher.dispatch(ToolCall("scope-1", "repo_read_text", {"path": ".env"}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert result.reason_code == reason
    assert not result.executed
    assert ".env" not in repr(result)


def test_registered_name_with_changed_trusted_metadata_is_not_executable() -> None:
    altered = ToolDefinition(
        "repo_read_text",
        "Wrong capability.",
        create_readonly_tool_registry().get("repo_read_text").arguments_model,
        capabilities=frozenset({Capability.REPOSITORY_SEARCH}),
        resource_fields=("path",),
    )
    registry = ToolRegistry((altered,))
    dispatcher = _dispatcher(registry)

    result = dispatcher.dispatch(ToolCall("r3", "repo_read_text", {"path": "x.py"}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert result.reason_code == "allowlist_mismatch"
    assert not result.executed


def test_dispatch_limits_cannot_exceed_hard_ceilings() -> None:
    with pytest.raises(ValueError):
        ToolDispatchLimits(max_output_bytes=32_769)
    with pytest.raises(ValueError):
        ToolDispatchLimits(max_execution_seconds=30.1)


def test_result_item_limit_applies_across_all_payload_lists() -> None:
    payload, truncated = _cap_payload_items(
        {"issues": ["syntax_error"], "symbols": ["one", "two"]}, 2
    )

    assert payload == {"issues": ["syntax_error"], "symbols": ["one"], "truncated": True}
    assert truncated
