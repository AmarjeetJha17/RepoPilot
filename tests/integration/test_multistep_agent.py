"""Linux integration tests for opt-in orchestration with actual staged reads."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.agent.multistep import MultiStepAgentOrchestrator, MultiStepConfig
from repopilot.context import RepositoryIntelligence
from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ModelRequest,
    ModelResponse,
    ModelRole,
    TextResponse,
    ToolCallResponse,
)
from repopilot.providers.mock import MockModelProvider
from repopilot.sandbox.workspace import WorkspaceHandle, WorkspaceManager
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
)
from repopilot.tools import create_readonly_tool_registry
from repopilot.tools.dispatcher import ReadOnlyToolDispatcher, workspace_identity_for_handle
from tests.fixtures.repository_intelligence import create_repository

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux workspace boundary."),
]

MODEL = ModelIdentifier("mock", "integration-test")


class _CapturingMockProvider(MockModelProvider):
    def __init__(self, outcomes: tuple[ModelResponse, ...]) -> None:
        super().__init__(outcomes)
        self.requests: list[ModelRequest] = []

    async def next_action(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return await super().next_action(request)


def _workflow(tmp_path: Path):
    source, source_files = create_repository(tmp_path)
    original = {source / relative: content for relative, content in source_files.items()}
    staging = tmp_path / "staging"
    staging.mkdir()
    manager = WorkspaceManager(temp_root=staging)
    handle: WorkspaceHandle = manager.prepare(source)
    run_id = uuid4()
    registry = create_readonly_tool_registry()
    authorization = AuthorizationContext(
        run_id=str(run_id),
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.REPOSITORY_READ, Capability.REPOSITORY_SEARCH}),
    )
    dispatcher = ReadOnlyToolDispatcher(
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        authorization=authorization,
        manager=manager,
        handle=handle,
        intelligence=RepositoryIntelligence(manager, handle),
    )
    return source, original, manager, registry, dispatcher, run_id


def test_real_read_is_correlated_as_untrusted_feedback_without_source_writes(
    tmp_path: Path,
) -> None:
    source, source_before, manager, registry, dispatcher, run_id = _workflow(tmp_path)
    call = ToolCall("actual-read-1", "repo_read_text", {"path": "notes/readme.txt"})
    provider = _CapturingMockProvider(
        (
            ToolCallResponse(MODEL, (call,), FinishReason.TOOL_CALLS),
            TextResponse(MODEL, "The file contains a needle.", FinishReason.STOP),
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
                MultiStepConfig(
                    "Inspect the readme.", MODEL, run_id, allow_repository_feedback=True
                )
            )
        )

        assert result.run.status.value == "PARTIAL"
        assert not result.run.verified
        assert len(provider.requests) == 2
        feedback_message = provider.requests[1].messages[-1]
        assert feedback_message.role is ModelRole.TOOL
        assert feedback_message.tool_call_id == call.id
        envelope = json.loads(feedback_message.content)
        assert envelope["status"] == "success"
        assert envelope["executed"] is True
        assert envelope["trust"] == "untrusted_repository_data"
        assert envelope["payload"]["text"].startswith("alpha needle")
        assert all(
            event.call_id != call.id or event.execution_status is not None
            for event in result.events
        )
        assert {path: path.read_bytes() for path in source_before} == source_before
        assert source.exists()
    finally:
        manager.close()
