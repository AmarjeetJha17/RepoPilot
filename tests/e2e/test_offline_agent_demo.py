"""Acceptance tests for the deterministic, offline agent demonstration."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest
from openai import AsyncOpenAI
from openai.types.responses import Response

from repopilot.agent.budget import BudgetConfig
from repopilot.agent.loop import (
    AgentLoopConfig,
    AgentOrchestrator,
    AgentRunCancelled,
    OrchestrationOutcome,
    ProposalOutcome,
)
from repopilot.agent.state import RunStatus
from repopilot.application.offline_demo import render_offline_demo, run_offline_demo
from repopilot.providers.adapters.openai import OpenAIModelProvider
from repopilot.providers.base import (
    FinishReason,
    InvalidProviderResponseError,
    ModelIdentifier,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelRole,
    TextResponse,
)
from repopilot.providers.mock import MockModelProvider
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
)
from repopilot.tools import ToolRegistry

pytestmark = pytest.mark.e2e

RUN_ID = UUID("44444444-4444-4444-8444-444444444441")
MODEL = ModelIdentifier("mock", "e2e-test")
NOW = datetime(2026, 11, 20, 12, tzinfo=UTC)


def _workspace(root: Path) -> tuple[Path, str]:
    source = root / "demo.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    return source, hashlib.sha256(source.read_bytes()).hexdigest()


def test_offline_scenarios_have_expected_status_and_decisions(tmp_path: Path) -> None:
    source, before = _workspace(tmp_path)

    scenarios = {item.name: item.run for item in run_offline_demo(tmp_path)}

    allowed = scenarios["allowed_proposal"]
    assert allowed.run.status is RunStatus.PARTIAL
    assert allowed.run.transition_history[-1].reason_code == "authorized_proposal_not_executed"
    assert allowed.proposal_decisions[0].outcome is ProposalOutcome.AUTHORIZED_NOT_EXECUTED
    assert allowed.proposal_decisions[0].policy_decision is not None
    assert allowed.proposal_decisions[0].policy_decision.decision is PolicyDecision.ALLOW
    assert allowed.budget_snapshot.usage.input_tokens == 18
    assert allowed.budget_snapshot.usage.output_tokens == 5

    denied = scenarios["denied_operation"]
    assert denied.run.status is RunStatus.BLOCKED
    assert denied.proposal_decisions[0].policy_decision is not None
    assert denied.proposal_decisions[0].policy_decision.decision is PolicyDecision.DENY

    approval = scenarios["approval_required"]
    assert approval.run.status is RunStatus.AWAITING_APPROVAL
    assert approval.proposal_decisions[0].outcome is ProposalOutcome.APPROVAL_REQUIRED
    assert approval.proposal_decisions[0].policy_decision is not None
    assert (
        approval.proposal_decisions[0].policy_decision.decision is PolicyDecision.REQUIRE_APPROVAL
    )
    assert approval.proposal_decisions[0].policy_decision.approval_request is not None

    text = scenarios["text_response"]
    assert text.outcome is OrchestrationOutcome.TEXT_RESPONSE
    assert text.run.status is RunStatus.PARTIAL
    assert text.run.verified is False
    assert text.run.verification_evidence is None
    assert text.response_summary is not None
    assert "offline demo response body" not in repr(text)

    failed = scenarios["provider_failure"]
    assert failed.outcome is OrchestrationOutcome.PROVIDER_ERROR
    assert failed.run.status is RunStatus.FAILED
    assert failed.error_code.value == "provider_unavailable"

    for result in scenarios.values():
        assert result.run.verified is False
        assert result.run.verification_evidence is None
        assert not hasattr(result, "tool_results")

    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_repeated_demo_runs_have_same_logical_results(tmp_path: Path) -> None:
    _workspace(tmp_path)

    first = run_offline_demo(tmp_path)
    second = run_offline_demo(tmp_path)

    assert [item.name for item in first] == [item.name for item in second]
    for left, right in zip(first, second, strict=True):
        assert left.run.run.run_id == right.run.run.run_id
        assert left.run.run.status is right.run.run.status
        assert left.run.run.transition_history == right.run.run.transition_history
        assert left.run.events == right.run.events
        assert left.run.events_dropped == right.run.events_dropped == 0


def test_demo_output_reports_decisions_without_proposal_contents(tmp_path: Path) -> None:
    _workspace(tmp_path)

    output = render_offline_demo(run_offline_demo(tmp_path))

    assert "Scenario: allowed_proposal" in output
    assert "Authorization: ALLOW" in output
    assert "Authorization: DENY" in output
    assert "Authorization: REQUIRE_APPROVAL" in output
    assert "Tools executed: no" in output
    assert "Independently verified: no" in output
    assert "offline demo response body" not in output
    assert "VALUE = 2" not in output


def test_provider_failure_does_not_change_synthetic_repository(tmp_path: Path) -> None:
    source, before = _workspace(tmp_path)

    failed = next(
        item.run for item in run_offline_demo(tmp_path) if item.name == "provider_failure"
    )

    assert failed.run.status is RunStatus.FAILED
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_demo_uses_only_mock_providers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace(tmp_path)

    def reject_live_provider(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("The offline demo must not invoke an OpenAI provider.")

    monkeypatch.setattr(OpenAIModelProvider, "next_action", reject_live_provider)

    assert len(run_offline_demo(tmp_path)) == 5


def test_request_budget_and_event_caps_remain_enforced(tmp_path: Path) -> None:
    provider = MockModelProvider((TextResponse(MODEL, "safe", FinishReason.STOP),))
    registry = ToolRegistry()
    context = AuthorizationContext(
        str(RUN_ID), tmp_path, ExecutionWorkspace.SOURCE, "e2e", frozenset()
    )
    orchestrator = AgentOrchestrator(
        provider=provider,
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry, clock=lambda: NOW),
        clock=lambda: NOW,
        monotonic=lambda: 10.0,
    )
    config = AgentLoopConfig(
        "Budget test task.",
        MODEL,
        RUN_ID,
        context,
        tmp_path,
        max_model_requests=0,
        budget_limits=BudgetConfig(max_model_requests=30),
        max_events=1,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.run.status is RunStatus.PARTIAL
    assert result.error_code.value == "model_request_limit"
    assert result.model_requests == provider.invocation_count == 0
    assert len(result.events) <= 1
    assert result.events_dropped > 0


def test_cancellation_is_propagated_without_retry_or_side_effects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def check() -> None:
        source, before = _workspace(tmp_path)
        response = TextResponse(MODEL, "safe", FinishReason.STOP)
        provider = MockModelProvider((response,), wait_before_response=asyncio.Event())
        invoked = asyncio.Event()
        original_next_action = provider.next_action

        async def signal_invocation(request: ModelRequest) -> ModelResponse:
            invoked.set()
            return await original_next_action(request)

        monkeypatch.setattr(provider, "next_action", signal_invocation)
        registry = ToolRegistry()
        context = AuthorizationContext(
            str(RUN_ID), tmp_path, ExecutionWorkspace.SOURCE, "e2e", frozenset()
        )
        orchestrator = AgentOrchestrator(
            provider=provider,
            registry=registry,
            policy_engine=DefaultPolicyEngine(registry, clock=lambda: NOW),
            clock=lambda: NOW,
        )
        config = AgentLoopConfig("Cancel task.", MODEL, RUN_ID, context, tmp_path)
        task = asyncio.create_task(orchestrator.run(config))
        await invoked.wait()
        task.cancel()

        with pytest.raises(AgentRunCancelled) as cancelled:
            await task
        assert cancelled.value.result.run.status is RunStatus.CANCELLED
        assert provider.invocation_count == 1
        assert hashlib.sha256(source.read_bytes()).hexdigest() == before

    asyncio.run(check())


def test_reasoning_continuation_stays_rejected_with_a_fake_sdk_client() -> None:
    class FakeResponses:
        async def create(self, **_kwargs: object) -> Response:
            return Response.model_construct(
                status="completed",
                incomplete_details=None,
                model="gpt-test",
                usage=None,
                output=[
                    SimpleNamespace(type="reasoning", status="completed", summary=[]),
                    SimpleNamespace(
                        type="message",
                        status="completed",
                        role="assistant",
                        content=[SimpleNamespace(type="output_text", text="not accepted")],
                    ),
                ],
            )

    class FakeClient:
        responses = FakeResponses()

        def with_options(self, **_kwargs: object) -> FakeClient:
            return self

    provider = OpenAIModelProvider(client=cast(AsyncOpenAI, FakeClient()))
    request = ModelRequest(
        ModelIdentifier("openai", "gpt-test"),
        (ModelMessage(ModelRole.USER, "offline test"),),
    )

    with pytest.raises(InvalidProviderResponseError):
        asyncio.run(provider.next_action(request))
