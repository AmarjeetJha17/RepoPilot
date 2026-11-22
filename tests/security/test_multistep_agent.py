"""Security boundaries for opt-in multi-step read-only orchestration."""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.agent.multistep import MultiStepAgentOrchestrator, MultiStepConfig
from repopilot.context import RepositoryIntelligence
from repopilot.providers.base import FinishReason, ModelIdentifier, TextResponse, ToolCallResponse
from repopilot.providers.mock import MockModelProvider
from repopilot.sandbox.workspace import WorkspaceManager
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
)
from repopilot.tools import create_readonly_tool_registry
from repopilot.tools.dispatcher import (
    ReadOnlyToolDispatcher,
    workspace_identity_for_handle,
)
from tests.fixtures.repository_intelligence import create_repository

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux workspace boundary."),
]

MODEL = ModelIdentifier("mock", "security-test")


def test_sensitive_file_denial_stops_before_handler_or_feedback(tmp_path: Path) -> None:
    source, files = create_repository(tmp_path)
    env_file = source / ".env"
    env_file.write_text("API_KEY=synthetic-secret", encoding="utf-8")
    source_before = {source / relative: content for relative, content in files.items()}
    source_before[env_file] = env_file.read_bytes()
    staging = tmp_path / "staging"
    staging.mkdir()
    manager = WorkspaceManager(temp_root=staging)
    handle = manager.prepare(source)
    run_id = uuid4()
    registry = create_readonly_tool_registry()
    authorization = AuthorizationContext(
        run_id=str(run_id),
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.REPOSITORY_READ}),
    )
    dispatcher = ReadOnlyToolDispatcher(
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        authorization=authorization,
        manager=manager,
        handle=handle,
        intelligence=RepositoryIntelligence(manager, handle),
    )
    secret_read = ToolCall("sensitive-1", "repo_read_text", {"path": ".env"})
    provider = MockModelProvider(
        (
            ToolCallResponse(MODEL, (secret_read,), FinishReason.TOOL_CALLS),
            TextResponse(MODEL, "must not be requested", FinishReason.STOP),
        )
    )
    orchestrator = MultiStepAgentOrchestrator(
        provider=provider,
        registry=registry,
        dispatcher=dispatcher,
    )

    try:
        result = asyncio.run(
            orchestrator.run(
                MultiStepConfig("Inspect config.", MODEL, run_id, allow_repository_feedback=True)
            )
        )

        assert result.outcome.value == "tool_execution_failed"
        assert result.run.status.value == "BLOCKED"
        assert provider.invocation_count == 1
        assert len(result.tool_results) == 1
        assert result.tool_results[0].call_id == secret_read.id
        assert not result.tool_results[0].ok
        assert json.loads(result.tool_results[0].output)["status"] == "policy_denied"
        assert json.loads(result.tool_results[0].output)["executed"] is False
        assert "synthetic-secret" not in result.tool_results[0].output
        assert all(event.reason_code != str(env_file) for event in result.events)
        assert all(
            not event.reason_code or "synthetic-secret" not in event.reason_code
            for event in result.events
        )
        assert {path: path.read_bytes() for path in source_before} == source_before
        assert not (handle.staging_root / ".env").exists()

        dispatcher._authorization = replace(authorization, workspace_identity="workspace:forged")
        valid_read = ToolCall("wrong-workspace-1", "repo_read_text", {"path": "pkg/first.py"})
        wrong_identity_provider = MockModelProvider(
            (ToolCallResponse(MODEL, (valid_read,), FinishReason.TOOL_CALLS),)
        )
        wrong_identity_result = asyncio.run(
            MultiStepAgentOrchestrator(
                provider=wrong_identity_provider,
                registry=registry,
                dispatcher=dispatcher,
            ).run(
                MultiStepConfig(
                    "Read a source file.", MODEL, run_id, allow_repository_feedback=True
                )
            )
        )
        assert wrong_identity_result.run.status.value == "BLOCKED"
        assert wrong_identity_provider.invocation_count == 1
        assert wrong_identity_result.tool_results[0].call_id == valid_read.id
        assert not wrong_identity_result.tool_results[0].ok
        assert "workspace_binding_mismatch" in wrong_identity_result.tool_results[0].output
        assert {path: path.read_bytes() for path in source_before} == source_before
    finally:
        manager.close()
