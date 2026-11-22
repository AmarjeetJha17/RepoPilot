"""Security tests for execution, policy, and workspace binding boundaries."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from threading import Event

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.context import RepositoryIntelligence
from repopilot.sandbox.workspace import WorkspaceHandle, WorkspaceManager
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
    PolicyDecisionResult,
    PolicyReasonCode,
)
from repopilot.tools import create_readonly_tool_registry
from repopilot.tools.dispatcher import (
    ReadOnlyToolDispatcher,
    ToolExecutionStatus,
    workspace_identity_for_handle,
)
from tests.fixtures.repository_intelligence import create_repository

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux workspace boundary."),
]


class _FixedPolicy:
    def __init__(self, result: PolicyDecisionResult) -> None:
        self.result = result
        self.calls = 0

    def authorize(self, *_args: object) -> PolicyDecisionResult:
        self.calls += 1
        return self.result


def _prepared(
    tmp_path: Path,
    *,
    allowed: frozenset[Capability] | None = None,
) -> tuple[Path, WorkspaceManager, WorkspaceHandle, ReadOnlyToolDispatcher]:
    source, _files = create_repository(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    manager = WorkspaceManager(temp_root=staging)
    handle = manager.prepare(source)
    registry = create_readonly_tool_registry()
    authorization = AuthorizationContext(
        "readonly-security-test",
        handle.staging_root,
        ExecutionWorkspace.STAGING,
        workspace_identity_for_handle(handle),
        (
            frozenset({Capability.REPOSITORY_READ, Capability.REPOSITORY_SEARCH})
            if allowed is None
            else allowed
        ),
    )
    dispatcher = ReadOnlyToolDispatcher(
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        authorization=authorization,
        manager=manager,
        handle=handle,
        intelligence=RepositoryIntelligence(manager, handle),
    )
    return source, manager, handle, dispatcher


def test_denial_happens_before_any_handler_invocation(tmp_path: Path, monkeypatch) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path, allowed=frozenset())

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("A denied proposal must not reach the reader.")

    monkeypatch.setattr(dispatcher._intelligence, "read_text", forbidden)
    result = dispatcher.dispatch(ToolCall("deny-1", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert not result.executed
    manager.close()


def test_approval_required_result_never_reaches_handler(tmp_path: Path, monkeypatch) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)
    approval = PolicyDecisionResult(
        PolicyDecision.REQUIRE_APPROVAL,
        PolicyReasonCode.LIVE_MODIFICATION_APPROVAL_REQUIRED,
        dispatcher._authorization.run_id,
        "approval-1",
        (Capability.REPOSITORY_READ,),
    )
    fixed = _FixedPolicy(approval)
    dispatcher._policy = fixed

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Approval is not execution permission.")

    monkeypatch.setattr(dispatcher._intelligence, "read_text", forbidden)
    result = dispatcher.dispatch(ToolCall("approval-1", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.APPROVAL_REQUIRED
    assert fixed.calls == 1
    assert not result.executed
    manager.close()


def test_stale_policy_result_is_not_accepted_as_allow(tmp_path: Path, monkeypatch) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)
    fixed = _FixedPolicy(
        PolicyDecisionResult(
            PolicyDecision.ALLOW,
            PolicyReasonCode.CAPABILITY_ALLOWED,
            dispatcher._authorization.run_id,
            "different-call",
            (Capability.REPOSITORY_READ,),
        )
    )
    dispatcher._policy = fixed

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("A stale decision must not execute the handler.")

    monkeypatch.setattr(dispatcher._intelligence, "read_text", forbidden)
    result = dispatcher.dispatch(ToolCall("fresh-call", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert result.reason_code == "invalid_policy_result"
    assert not result.executed
    manager.close()


@pytest.mark.parametrize("binding", ["copied_handle", "wrong_identity", "foreign_manager"])
def test_workspace_binding_mismatches_fail_closed(tmp_path: Path, binding: str) -> None:
    _source, manager, handle, dispatcher = _prepared(tmp_path)
    if binding == "copied_handle":
        dispatcher._handle = replace(handle)
    elif binding == "wrong_identity":
        dispatcher._authorization = replace(
            dispatcher._authorization, workspace_identity="workspace:wrong"
        )
    else:
        foreign = WorkspaceManager(temp_root=tmp_path / "staging")
        dispatcher._manager = foreign

    result = dispatcher.dispatch(ToolCall("binding-1", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.WORKSPACE_FAILURE
    assert not result.executed
    manager.close()
    if foreign is not None:
        foreign.close()


def test_cleaned_workspace_is_rejected(tmp_path: Path) -> None:
    _source, manager, handle, dispatcher = _prepared(tmp_path)
    manager.cleanup(handle)

    result = dispatcher.dispatch(ToolCall("clean-1", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.WORKSPACE_FAILURE
    assert not result.executed


@pytest.mark.parametrize("path", ["../outside", "C:\\Windows\\win.ini", "\\\\host\\share\\x"])
def test_traversal_and_platform_paths_are_denied_before_handler(
    tmp_path: Path, monkeypatch, path: str
) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Invalid resource scope must not reach the handler.")

    monkeypatch.setattr(dispatcher._intelligence, "read_text", forbidden)
    result = dispatcher.dispatch(ToolCall("path-1", "repo_read_text", {"path": path}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert not result.executed
    manager.close()


def test_sensitive_resource_is_denied_without_echoing_host_or_contents(
    tmp_path: Path, monkeypatch
) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Sensitive path must not reach the handler.")

    monkeypatch.setattr(dispatcher._intelligence, "read_text", forbidden)
    result = dispatcher.dispatch(ToolCall("secret-1", "repo_read_text", {"path": ".env"}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert result.reason_code == PolicyReasonCode.SENSITIVE_RESOURCE.value
    assert str(tmp_path) not in repr(result)
    assert "synthetic-secret" not in repr(result)
    manager.close()


def test_symlink_substitution_is_rejected_by_policy_and_no_follow_reader(tmp_path: Path) -> None:
    _source, manager, handle, dispatcher = _prepared(tmp_path)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("synthetic external data", encoding="utf-8")
    staged = handle.staging_root / "pkg/first.py"
    staged.unlink()
    staged.symlink_to(outside)

    result = dispatcher.dispatch(ToolCall("link-1", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.POLICY_DENIED
    assert "synthetic external data" not in repr(result)
    assert str(outside) not in repr(result)
    assert outside.read_text(encoding="utf-8") == "synthetic external data"
    manager.close()


def test_duplicate_batch_ids_are_rejected_before_any_execution(tmp_path: Path, monkeypatch) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)
    calls = 0
    original = dispatcher._intelligence.read_text

    def counted(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(dispatcher._intelligence, "read_text", counted)
    results = dispatcher.dispatch_batch(
        (
            ToolCall("duplicate", "repo_read_text", {"path": "pkg/first.py"}),
            ToolCall("duplicate", "repo_read_text", {"path": "notes/readme.txt"}),
        )
    )

    assert len(results) == 1
    assert results[0].status is ToolExecutionStatus.VALIDATION_FAILURE
    assert results[0].reason_code == "duplicate_call_id"
    assert calls == 0
    manager.close()


def test_batch_stops_after_policy_denial(tmp_path: Path) -> None:
    _source, manager, _handle, dispatcher = _prepared(
        tmp_path, allowed=frozenset({Capability.REPOSITORY_READ})
    )
    results = dispatcher.dispatch_batch(
        (
            ToolCall("batch-read", "repo_read_text", {"path": "pkg/first.py"}),
            ToolCall(
                "batch-search",
                "repo_search_literal",
                {"paths": ["notes/readme.txt"], "query": "needle"},
            ),
            ToolCall("batch-read-2", "repo_read_text", {"path": "notes/readme.txt"}),
        )
    )

    assert [result.status for result in results] == [
        ToolExecutionStatus.SUCCESS,
        ToolExecutionStatus.POLICY_DENIED,
    ]
    manager.close()


def test_dispatch_uses_no_network_shell_or_provider(tmp_path: Path, monkeypatch) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Read-only tool dispatch must remain local.")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    result = dispatcher.dispatch(ToolCall("local-1", "repo_read_text", {"path": "pkg/first.py"}))

    assert result.status is ToolExecutionStatus.SUCCESS
    assert not hasattr(dispatcher, "_provider")
    manager.close()


def test_handler_failure_is_safe_and_not_reported_as_success(tmp_path: Path, monkeypatch) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic private path and content")

    monkeypatch.setattr(dispatcher._intelligence, "read_text", fail)
    result = dispatcher.dispatch(
        ToolCall("handler-fail", "repo_read_text", {"path": "pkg/first.py"})
    )

    assert result.status is ToolExecutionStatus.EXECUTION_FAILURE
    assert result.executed
    assert result.reason_code == "handler_failure"
    assert "synthetic private path" not in repr(result)
    assert result.payload_json is None
    manager.close()


def test_cancellation_before_dispatch_prevents_policy_and_handler(tmp_path: Path) -> None:
    _source, manager, _handle, dispatcher = _prepared(tmp_path)
    cancellation = Event()
    cancellation.set()
    result = dispatcher.dispatch(
        ToolCall("cancel-1", "repo_read_text", {"path": "pkg/first.py"}),
        cancellation=cancellation,
    )

    assert result.status is ToolExecutionStatus.CANCELLED
    assert not result.executed
    manager.close()
