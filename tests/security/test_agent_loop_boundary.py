"""Security boundary checks for model-proposed tool calls."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel

from repopilot.agent.contracts import ToolCall
from repopilot.agent.loop import AgentLoopConfig, AgentOrchestrator, ProposalOutcome
from repopilot.providers.base import FinishReason, ModelIdentifier, ToolCallResponse
from repopilot.providers.mock import MockModelProvider
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, DefaultPolicyEngine, ExecutionWorkspace
from repopilot.tools import ToolDefinition, ToolRegistry

RUN_ID = UUID("222577c1-26a3-40b1-9058-1116a1a13ab1")
MODEL = ModelIdentifier("mock", "security-test")
MODEL_WRITE_PAYLOAD = "MODEL_WRITE_PAYLOAD_SECRET"


class WriteArguments(BaseModel):
    path: str
    content: str


def test_authorized_write_proposal_never_changes_workspace(tmp_path: Path) -> None:
    target = tmp_path / "keep.txt"
    target.write_text("original", encoding="utf-8")
    call = ToolCall(
        "write-call", "write_file", {"path": "keep.txt", "content": MODEL_WRITE_PAYLOAD}
    )
    provider = MockModelProvider((ToolCallResponse(MODEL, (call,), FinishReason.TOOL_CALLS),))
    definition = ToolDefinition(
        "write_file",
        "Write one staged file.",
        WriteArguments,
        capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
        resource_fields=("path",),
    )
    registry = ToolRegistry((definition,))
    authorization = AuthorizationContext(
        str(RUN_ID),
        tmp_path,
        ExecutionWorkspace.STAGING,
        "security-baseline",
        frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )
    orchestrator = AgentOrchestrator(
        provider=provider,
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        clock=lambda: datetime(2026, 11, 19, tzinfo=UTC),
    )

    result = asyncio.run(
        orchestrator.run(
            AgentLoopConfig("Propose a staged edit.", MODEL, RUN_ID, authorization, tmp_path)
        )
    )

    assert result.proposal_decisions[0].outcome is ProposalOutcome.AUTHORIZED_NOT_EXECUTED
    assert target.read_text(encoding="utf-8") == "original"
    assert set(path.name for path in tmp_path.iterdir()) == {"keep.txt"}
    assert "Propose a staged edit." not in repr(result.events)
    assert MODEL_WRITE_PAYLOAD not in repr(result.events)
    assert not hasattr(result, "tool_results")
