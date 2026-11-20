"""Compose the existing runtime for a small, non-executing offline demonstration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from repopilot.agent.budget import BudgetConfig
from repopilot.agent.contracts import ToolCall
from repopilot.agent.loop import AgentLoopConfig, AgentOrchestrator, AgentRunResult
from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ProviderUnavailableError,
    TextResponse,
    TokenUsage,
    ToolCallResponse,
)
from repopilot.providers.mock import MockModelProvider
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
)
from repopilot.tools import ToolDefinition, ToolRegistry

_MODEL = ModelIdentifier("mock", "offline-demo-v1")
_NOW = datetime(2026, 11, 20, 12, tzinfo=UTC)
_RUN_IDS = {
    "allowed_proposal": UUID("44444444-4444-4444-8444-444444444441"),
    "denied_operation": UUID("44444444-4444-4444-8444-444444444442"),
    "approval_required": UUID("44444444-4444-4444-8444-444444444443"),
    "text_response": UUID("44444444-4444-4444-8444-444444444444"),
    "provider_failure": UUID("44444444-4444-4444-8444-444444444445"),
}


class _ReadArguments(BaseModel):
    path: str


class _HostOperationArguments(BaseModel):
    operation: Literal["inspect"]


class _LiveWriteArguments(BaseModel):
    path: str
    content: str


@dataclass(frozen=True, slots=True)
class OfflineDemoScenario:
    """One safe run result paired with a fixed scenario label."""

    name: str
    run: AgentRunResult


def run_offline_demo(workspace: Path) -> tuple[OfflineDemoScenario, ...]:
    """Run five fixed scenarios against a disposable synthetic workspace without execution."""
    if not isinstance(workspace, Path) or not workspace.is_dir():
        raise ValueError("Offline demo requires an existing synthetic workspace directory.")

    read_definition = ToolDefinition(
        "read_file",
        "Read one synthetic source file.",
        _ReadArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
        resource_fields=("path",),
    )
    denied_definition = ToolDefinition(
        "host_operation",
        "Request a prohibited host operation.",
        _HostOperationArguments,
        capabilities=frozenset({Capability.HOST_COMMAND_EXECUTION}),
    )
    live_write_definition = ToolDefinition(
        "apply_live_change",
        "Request a live repository change.",
        _LiveWriteArguments,
        capabilities=frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
        resource_fields=("path",),
    )

    return (
        _run_scenario(
            "allowed_proposal",
            workspace,
            read_definition,
            frozenset({Capability.REPOSITORY_READ}),
            ToolCallResponse(
                _MODEL,
                (ToolCall("demo-read-1", "read_file", {"path": "demo.py"}),),
                FinishReason.TOOL_CALLS,
                TokenUsage(18, 5),
            ),
        ),
        _run_scenario(
            "denied_operation",
            workspace,
            denied_definition,
            frozenset({Capability.HOST_COMMAND_EXECUTION}),
            ToolCallResponse(
                _MODEL,
                (ToolCall("demo-denied-1", "host_operation", {"operation": "inspect"}),),
                FinishReason.TOOL_CALLS,
                TokenUsage(9, 2),
            ),
        ),
        _run_scenario(
            "approval_required",
            workspace,
            live_write_definition,
            frozenset({Capability.LIVE_REPOSITORY_MODIFICATION}),
            ToolCallResponse(
                _MODEL,
                (
                    ToolCall(
                        "demo-approval-1",
                        "apply_live_change",
                        {"path": "demo.py", "content": "VALUE = 2\\n"},
                    ),
                ),
                FinishReason.TOOL_CALLS,
                TokenUsage(12, 3),
            ),
        ),
        _run_scenario(
            "text_response",
            workspace,
            None,
            frozenset(),
            TextResponse(
                _MODEL,
                "offline demo response body",
                FinishReason.STOP,
                TokenUsage(7, 2),
            ),
        ),
        _run_scenario(
            "provider_failure",
            workspace,
            None,
            frozenset(),
            ProviderUnavailableError(),
        ),
    )


def _run_scenario(
    name: str,
    workspace: Path,
    definition: ToolDefinition | None,
    capabilities: frozenset[Capability],
    outcome: TextResponse | ToolCallResponse | ProviderUnavailableError,
) -> OfflineDemoScenario:
    run_id = _RUN_IDS[name]
    registry = ToolRegistry(() if definition is None else (definition,))
    authorization = AuthorizationContext(
        str(run_id),
        workspace,
        ExecutionWorkspace.SOURCE,
        "offline-demo-synthetic-repository-v1",
        capabilities,
    )
    provider = MockModelProvider((outcome,))
    orchestrator = AgentOrchestrator(
        provider=provider,
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry, clock=lambda: _NOW),
        clock=lambda: _NOW,
        monotonic=lambda: 100.0,
    )
    result = asyncio.run(
        orchestrator.run(
            AgentLoopConfig(
                task=f"Synthetic offline scenario: {name}.",
                model=_MODEL,
                run_id=run_id,
                authorization=authorization,
                workspace=workspace,
                budget_limits=BudgetConfig(max_model_requests=30, max_run_seconds=900),
                max_events=24,
                max_event_bytes=8_192,
            )
        )
    )
    return OfflineDemoScenario(name, result)


def render_offline_demo(scenarios: tuple[OfflineDemoScenario, ...]) -> str:
    """Render safe scenario metadata, omitting prompts, responses, arguments, and file data."""
    lines = ["RepoPilot offline simulation (mock provider; proposed tools are never executed)"]
    for scenario in scenarios:
        result = scenario.run
        reason = result.run.transition_history[-1].reason_code or "none"
        usage = result.budget_snapshot.usage
        usage_text = (
            "unknown"
            if usage.input_tokens is None and usage.output_tokens is None
            else f"input={_known(usage.input_tokens)} output={_known(usage.output_tokens)}"
        )
        proposal = result.proposal_decisions[0] if result.proposal_decisions else None
        if proposal is None:
            proposal_text = "none"
            validation_text = "not applicable"
            authorization_text = "not evaluated"
        else:
            proposal_text = proposal.tool_name or "unknown"
            validation_text = "passed" if proposal.validation_error is None else "failed"
            decision = (
                None if proposal.policy_decision is None else proposal.policy_decision.decision
            )
            reason_code = (
                None
                if proposal.policy_decision is None
                else proposal.policy_decision.reason_code.value
            )
            authorization_text = (
                "not evaluated" if decision is None else f"{decision.name} ({reason_code})"
            )
        lines.extend(
            (
                "",
                f"Scenario: {scenario.name}",
                f"  Run ID: {result.run.run_id}",
                f"  Status: {result.run.status.value}",
                f"  Termination reason: {reason}",
                f"  Model requests: {result.model_requests}",
                f"  Known token usage: {usage_text}",
                f"  Proposed tool: {proposal_text}",
                f"  Validation: {validation_text}",
                f"  Authorization: {authorization_text}",
                f"  Events: {len(result.events)} retained, {result.events_dropped} dropped",
                "  Tools executed: no",
                f"  Independently verified: {'yes' if result.run.verified else 'no'}",
            )
        )
    return "\n".join(lines)


def _known(count: int | None) -> str:
    return "unknown" if count is None else str(count)
