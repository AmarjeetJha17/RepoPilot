"""Integration checks for the composed agent, provider, registry, and policy."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel

from repopilot.agent.contracts import ToolCall
from repopilot.agent.loop import AgentLoopConfig, AgentOrchestrator, OrchestrationOutcome
from repopilot.agent.state import RunStatus
from repopilot.providers.base import FinishReason, ModelIdentifier, ToolCallResponse
from repopilot.providers.mock import MockModelProvider
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, DefaultPolicyEngine, ExecutionWorkspace
from repopilot.tools import ToolDefinition, ToolRegistry

RUN_ID = UUID("41424fc5-805a-4288-9b13-b3da5406bc34")
MODEL = ModelIdentifier("mock", "integration-test")


class ReadArguments(BaseModel):
    path: str


def test_mock_proposal_flows_through_registry_and_policy_without_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "source.py").write_text("unchanged", encoding="utf-8")
    call = ToolCall("call-1", "read_file", {"path": "source.py"})
    provider = MockModelProvider((ToolCallResponse(MODEL, (call,), FinishReason.TOOL_CALLS),))
    definition = ToolDefinition(
        "read_file",
        "Read one file.",
        ReadArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
        resource_fields=("path",),
    )
    registry = ToolRegistry((definition,))
    authorization = AuthorizationContext(
        str(RUN_ID),
        tmp_path,
        ExecutionWorkspace.SOURCE,
        "integration-baseline",
        frozenset({Capability.REPOSITORY_READ}),
    )
    orchestrator = AgentOrchestrator(
        provider=provider,
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        clock=lambda: datetime(2026, 11, 19, tzinfo=UTC),
    )

    result = asyncio.run(
        orchestrator.run(AgentLoopConfig("Inspect source.", MODEL, RUN_ID, authorization, tmp_path))
    )

    assert result.outcome is OrchestrationOutcome.AWAITING_EXECUTION
    assert result.run.status is RunStatus.PARTIAL
    assert provider.invocation_count == 1
    assert (tmp_path / "source.py").read_text(encoding="utf-8") == "unchanged"
