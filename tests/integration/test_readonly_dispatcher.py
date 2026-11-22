"""Linux integration tests for policy-gated read-only repository tool execution."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.context import RepositoryIntelligence
from repopilot.sandbox.workspace import WorkspaceHandle, WorkspaceManager
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
)
from repopilot.tools import create_readonly_tool_registry
from repopilot.tools.dispatcher import (
    ReadOnlyToolDispatcher,
    ToolDispatchLimits,
    ToolExecutionStatus,
    workspace_identity_for_handle,
)
from tests.fixtures.repository_intelligence import create_repository

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux workspace boundary."),
]


def _dispatcher(
    tmp_path: Path,
    *,
    allowed: frozenset[Capability] | None = None,
    sensitive: tuple[str, ...] = (),
    limits: ToolDispatchLimits | None = None,
) -> tuple[Path, WorkspaceManager, WorkspaceHandle, ReadOnlyToolDispatcher]:
    source, _files = create_repository(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    manager = WorkspaceManager(temp_root=staging)
    handle = manager.prepare(source)
    registry = create_readonly_tool_registry()
    authorization = AuthorizationContext(
        run_id="readonly-dispatch-test",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=(
            frozenset({Capability.REPOSITORY_READ, Capability.REPOSITORY_SEARCH})
            if allowed is None
            else allowed
        ),
        sensitive_resource_patterns=sensitive,
    )
    dispatcher = ReadOnlyToolDispatcher(
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        authorization=authorization,
        manager=manager,
        handle=handle,
        intelligence=RepositoryIntelligence(manager, handle),
        limits=limits,
    )
    return source, manager, handle, dispatcher


def test_all_four_tools_execute_and_return_real_bounded_payloads(tmp_path: Path) -> None:
    source, manager, _handle, dispatcher = _dispatcher(tmp_path)
    source_before = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    calls = (
        ToolCall("discover-1", "repo_discover_files", {"directory": ".", "max_files": 20}),
        ToolCall("read-1", "repo_read_text", {"path": "notes/readme.txt", "max_bytes": 100}),
        ToolCall(
            "search-1",
            "repo_search_literal",
            {"paths": ["notes/readme.txt"], "query": "needle"},
        ),
        ToolCall("index-1", "repo_index_python", {"paths": ["pkg/__init__.py"]}),
    )

    results = tuple(dispatcher.dispatch(call) for call in calls)

    assert [result.status for result in results] == [ToolExecutionStatus.SUCCESS] * 4
    assert all(result.executed and result.payload_json for result in results)
    discovered = json.loads(results[0].payload_json or "{}")
    read = json.loads(results[1].payload_json or "{}")
    searched = json.loads(results[2].payload_json or "{}")
    indexed = json.loads(results[3].payload_json or "{}")
    assert any(item["path"] == "pkg/__init__.py" for item in discovered["files"])
    assert read["text"].startswith("alpha needle")
    assert searched["matches"][0]["path"] == "notes/readme.txt"
    assert any(item["qualified_name"] == "Alpha.method.nested" for item in indexed["symbols"])
    assert all(result.payload_size_bytes <= 16_384 for result in results)
    assert not any(hasattr(result, "verified") for result in results)
    assert {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    } == source_before
    manager.close()


def test_directory_discovery_applies_application_sensitive_patterns(tmp_path: Path) -> None:
    _source, manager, _handle, dispatcher = _dispatcher(tmp_path, sensitive=("**/first.py",))

    result = dispatcher.dispatch(ToolCall("discover-2", "repo_discover_files", {"directory": "."}))

    paths = [item["path"] for item in json.loads(result.payload_json or "{}")["files"]]
    assert result.status is ToolExecutionStatus.SUCCESS
    assert "pkg/first.py" not in paths
    manager.close()


def test_output_byte_limit_returns_failure_without_payload(tmp_path: Path) -> None:
    _source, manager, _handle, dispatcher = _dispatcher(
        tmp_path, limits=ToolDispatchLimits(max_output_bytes=64)
    )

    result = dispatcher.dispatch(ToolCall("read-2", "repo_read_text", {"path": "notes/readme.txt"}))

    assert result.status is ToolExecutionStatus.OUTPUT_LIMIT_EXCEEDED
    assert result.executed
    assert result.truncated
    assert result.payload_json is None
    assert result.payload_size_bytes > 64
    manager.close()


def test_result_item_limit_truncates_discovery_deterministically(tmp_path: Path) -> None:
    _source, manager, _handle, dispatcher = _dispatcher(
        tmp_path, limits=ToolDispatchLimits(max_result_items=1)
    )

    result = dispatcher.dispatch(
        ToolCall("discover-cap", "repo_discover_files", {"directory": "."})
    )
    payload = json.loads(result.payload_json or "{}")

    assert result.status is ToolExecutionStatus.SUCCESS
    assert len(payload["files"]) == 1
    assert result.truncated
    assert payload["truncated"]
    manager.close()
