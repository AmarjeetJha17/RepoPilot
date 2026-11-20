"""Tests for the one-decision orchestration cycle; no tool handlers are installed."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from pydantic import BaseModel

from repopilot.agent.budget import BudgetConfig, BudgetReasonCode
from repopilot.agent.contracts import ToolCall
from repopilot.agent.loop import (
    AgentEventType,
    AgentLoopConfig,
    AgentOrchestrator,
    AgentRunCancelled,
    OrchestrationErrorCode,
    OrchestrationOutcome,
    ProposalOutcome,
)
from repopilot.agent.state import RunStatus
from repopilot.providers.base import (
    FinishReason,
    InvalidProviderResponseError,
    ModelIdentifier,
    ModelRequest,
    ModelResponse,
    ProviderAuthenticationError,
    ProviderRateLimitError,
    ProviderTimeoutError,
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
    PolicyDecision,
)
from repopilot.tools import ToolDefinition, ToolRegistry
from repopilot.tools.errors import ToolRegistryErrorCode

pytestmark = pytest.mark.unit

RUN_ID = UUID("e0846a82-6326-4dc0-8a47-cfb40f7bc499")
MODEL = ModelIdentifier("mock", "loop-test")
NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)


class ReadArguments(BaseModel):
    path: str


class _ScriptedProvider:
    def __init__(self, outcome: object) -> None:
        self.outcome = outcome
        self.requests: list[ModelRequest] = []

    async def next_action(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            return await self.outcome(request)
        return cast(ModelResponse, self.outcome)


def _setup(
    root: Path,
    response: object,
    *,
    capability: Capability = Capability.REPOSITORY_READ,
    allowed: frozenset[Capability] | None = None,
    monotonic: Callable[[], float] | None = None,
    **config_overrides: object,
) -> tuple[AgentOrchestrator, AgentLoopConfig, _ScriptedProvider, ToolRegistry]:
    definition = ToolDefinition(
        "read_file",
        "Read one synthetic source file.",
        ReadArguments,
        capabilities=frozenset({capability}),
        resource_fields=("path",),
    )
    registry = ToolRegistry((definition,))
    context = AuthorizationContext(
        run_id=str(RUN_ID),
        workspace_root=root,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity="synthetic-workspace-baseline",
        allowed_capabilities=frozenset({capability}) if allowed is None else allowed,
    )
    provider = _ScriptedProvider(response)
    policy = DefaultPolicyEngine(registry, clock=lambda: NOW)
    orchestrator = AgentOrchestrator(
        provider=cast(object, provider),
        registry=registry,
        policy_engine=policy,
        clock=lambda: NOW,
        monotonic=monotonic,
    )
    config = AgentLoopConfig(
        task="Inspect the synthetic repository.",
        model=MODEL,
        run_id=RUN_ID,
        authorization=context,
        workspace=root,
        **config_overrides,
    )
    return orchestrator, config, provider, registry


def _text(text: str = "Synthetic response.", usage: TokenUsage | None = None) -> TextResponse:
    return TextResponse(MODEL, text, FinishReason.STOP, usage)


def _tool_response(*calls: ToolCall) -> ToolCallResponse:
    return ToolCallResponse(MODEL, calls, FinishReason.TOOL_CALLS)


def _call(call_id: str = "call-1", path: str = "src/file.py") -> ToolCall:
    return ToolCall(call_id, "read_file", {"path": path})


def test_text_response_is_bounded_and_never_claims_verification(tmp_path: Path) -> None:
    provider = MockModelProvider((_text("private response content"),))
    registry = ToolRegistry()
    context = AuthorizationContext(
        str(RUN_ID),
        tmp_path,
        ExecutionWorkspace.SOURCE,
        "baseline",
        frozenset(),
    )
    orchestrator = AgentOrchestrator(
        provider=provider,
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        clock=lambda: NOW,
    )
    config = AgentLoopConfig(
        task="Task text that must not be copied into events.",
        model=MODEL,
        run_id=RUN_ID,
        authorization=context,
        workspace=tmp_path,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.TEXT_RESPONSE
    assert result.run.status is RunStatus.PARTIAL
    assert result.run.verified is False
    assert result.run.verification_evidence is None
    assert result.response_summary == "Text response received (24 chars; stop)."
    assert result.budget_snapshot.usage.input_tokens is None
    assert result.budget_snapshot.usage.output_tokens is None
    assert result.budget_snapshot.usage.missing_reports == 1
    assert "private response content" not in repr(result)
    assert "Task text" not in repr(result.events)
    assert provider.invocation_count == 1


def test_tool_proposal_is_validated_authorized_and_left_unexecuted(tmp_path: Path) -> None:
    target = tmp_path / "src" / "file.py"
    target.parent.mkdir()
    target.write_text("before", encoding="utf-8")
    response = _tool_response(_call())
    orchestrator, config, provider, _ = _setup(tmp_path, response)

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.AWAITING_EXECUTION
    assert result.run.status is RunStatus.PARTIAL
    assert result.run.verified is False
    assert len(result.proposal_decisions) == 1
    proposal = result.proposal_decisions[0]
    assert proposal.outcome is ProposalOutcome.AUTHORIZED_NOT_EXECUTED
    assert proposal.tool_name == "read_file"
    assert proposal.policy_decision is not None
    assert proposal.policy_decision.decision is PolicyDecision.ALLOW
    assert not hasattr(result, "tool_results")
    assert target.read_text(encoding="utf-8") == "before"
    assert len(provider.requests) == 1


def test_model_request_has_only_task_and_registered_schemas(tmp_path: Path) -> None:
    orchestrator, config, provider, registry = _setup(tmp_path, _text())

    asyncio.run(orchestrator.run(config))

    assert len(provider.requests) == 1
    request = provider.requests[0]
    assert request.model == MODEL
    assert [message.content for message in request.messages] == [config.task]
    assert request.tools == tuple(registry.export_schemas())
    assert request.timeout_seconds == config.request_timeout_seconds


def test_multiple_calls_receive_independent_policy_decisions(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a", encoding="utf-8")
    (tmp_path / "b.py").write_text("b", encoding="utf-8")
    response = _tool_response(_call("call-a", "a.py"), _call("call-b", "b.py"))
    orchestrator, config, _, _ = _setup(tmp_path, response, max_tool_calls_per_response=2)

    result = asyncio.run(orchestrator.run(config))

    assert [item.call_id for item in result.proposal_decisions] == ["call-a", "call-b"]
    assert all(
        item.policy_decision is not None and item.policy_decision.decision is PolicyDecision.ALLOW
        for item in result.proposal_decisions
    )
    assert [event.sequence for event in result.events] == list(range(1, len(result.events) + 1))


def test_invalid_arguments_and_unknown_tools_are_reported_independently(
    tmp_path: Path,
) -> None:
    bad_arguments = ToolCall("bad-args", "read_file", {"path": 3})  # type: ignore[dict-item]
    unknown = ToolCall("unknown-call", "not_registered", {"path": "a.py"})
    orchestrator, config, _, _ = _setup(
        tmp_path,
        _tool_response(bad_arguments, unknown),
        max_tool_calls_per_response=2,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.DENIED
    assert result.run.status is RunStatus.BLOCKED
    assert [item.validation_error for item in result.proposal_decisions] == [
        ToolRegistryErrorCode.INVALID_ARGUMENTS,
        ToolRegistryErrorCode.UNKNOWN_TOOL,
    ]
    assert all(item.policy_decision is None for item in result.proposal_decisions)
    assert result.proposal_decisions[1].tool_name is None


def test_policy_denial_blocks_without_execution(tmp_path: Path) -> None:
    orchestrator, config, _, _ = _setup(
        tmp_path,
        _tool_response(_call()),
        allowed=frozenset(),
    )

    result = asyncio.run(orchestrator.run(config))

    proposal = result.proposal_decisions[0]
    assert result.outcome is OrchestrationOutcome.DENIED
    assert result.run.status is RunStatus.BLOCKED
    assert proposal.outcome is ProposalOutcome.DENIED
    assert proposal.policy_decision is not None
    assert proposal.policy_decision.decision is PolicyDecision.DENY


def test_approval_required_stays_pending_without_model_consent(tmp_path: Path) -> None:
    orchestrator, config, provider, _ = _setup(
        tmp_path,
        _tool_response(_call()),
        capability=Capability.LIVE_REPOSITORY_MODIFICATION,
    )

    result = asyncio.run(orchestrator.run(config))

    proposal = result.proposal_decisions[0]
    assert result.outcome is OrchestrationOutcome.APPROVAL_REQUIRED
    assert result.run.status is RunStatus.AWAITING_APPROVAL
    assert proposal.outcome is ProposalOutcome.APPROVAL_REQUIRED
    assert proposal.policy_decision is not None
    assert proposal.policy_decision.approval_request is not None
    assert len(provider.requests) == 1


@pytest.mark.parametrize(
    ("error", "error_code"),
    [
        (ProviderAuthenticationError(), OrchestrationErrorCode.PROVIDER_AUTHENTICATION),
        (ProviderRateLimitError(), OrchestrationErrorCode.PROVIDER_RATE_LIMITED),
        (ProviderTimeoutError(), OrchestrationErrorCode.PROVIDER_TIMEOUT),
        (ProviderUnavailableError(), OrchestrationErrorCode.PROVIDER_UNAVAILABLE),
        (InvalidProviderResponseError(), OrchestrationErrorCode.INVALID_PROVIDER_RESPONSE),
    ],
)
def test_provider_errors_are_safe_and_terminal(
    tmp_path: Path,
    error: Exception,
    error_code: OrchestrationErrorCode,
) -> None:
    orchestrator, config, _, _ = _setup(tmp_path, error)

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.PROVIDER_ERROR
    assert result.run.status is RunStatus.FAILED
    assert result.error_code is error_code
    assert str(error) not in repr(result)


def test_request_deadline_bounds_provider_that_ignores_request_timeout(tmp_path: Path) -> None:
    async def hang(_request: ModelRequest) -> ModelResponse:
        await asyncio.Event().wait()
        return _text()

    orchestrator, config, _, _ = _setup(
        tmp_path,
        hang,
        request_timeout_seconds=0.01,
        run_timeout_seconds=1,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.PROVIDER_ERROR
    assert result.error_code is OrchestrationErrorCode.PROVIDER_TIMEOUT
    assert result.run.status is RunStatus.FAILED


def test_run_deadline_timeout_is_distinct_from_provider_timeout(tmp_path: Path) -> None:
    async def hang(_request: ModelRequest) -> ModelResponse:
        await asyncio.Event().wait()
        return _text()

    orchestrator, config, _, _ = _setup(
        tmp_path,
        hang,
        request_timeout_seconds=10,
        run_timeout_seconds=0.01,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.LIMIT_EXCEEDED
    assert result.run.status is RunStatus.PARTIAL
    assert result.error_code is OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED
    assert result.budget_reason_code is BudgetReasonCode.RUN_DEADLINE_EXCEEDED


def test_early_provider_timeout_is_not_misreported_as_run_deadline(tmp_path: Path) -> None:
    orchestrator, config, _, _ = _setup(
        tmp_path,
        ProviderTimeoutError(),
        request_timeout_seconds=10,
        run_timeout_seconds=1,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.PROVIDER_ERROR
    assert result.run.status is RunStatus.FAILED
    assert result.error_code is OrchestrationErrorCode.PROVIDER_TIMEOUT


def test_zero_request_budget_exhausts_without_provider_call(tmp_path: Path) -> None:
    orchestrator, config, provider, _ = _setup(
        tmp_path,
        _text(),
        max_model_requests=0,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.LIMIT_EXCEEDED
    assert result.error_code is OrchestrationErrorCode.MODEL_REQUEST_LIMIT
    assert result.run.status is RunStatus.PARTIAL
    assert provider.requests == []


def test_tool_call_limit_rejects_overflow_without_partial_dispatch(tmp_path: Path) -> None:
    response = _tool_response(_call("one"), _call("two"))
    orchestrator, config, _, _ = _setup(
        tmp_path,
        response,
        max_tool_calls_per_response=1,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.LIMIT_EXCEEDED
    assert result.error_code is OrchestrationErrorCode.TOO_MANY_TOOL_CALLS
    assert result.proposal_decisions == ()
    assert result.run.status is RunStatus.PARTIAL


def test_run_deadline_exhaustion_discards_late_response(tmp_path: Path) -> None:
    monotonic = [100.0]

    async def late(_request: ModelRequest) -> ModelResponse:
        monotonic[0] += 2
        return _text("late private text")

    orchestrator, config, _, _ = _setup(
        tmp_path,
        late,
        run_timeout_seconds=1,
        monotonic=lambda: monotonic[0],
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.LIMIT_EXCEEDED
    assert result.error_code is OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED
    assert result.run.status is RunStatus.PARTIAL
    assert result.response_summary is None


def test_task_cancellation_propagates_with_cancelled_run_snapshot(tmp_path: Path) -> None:
    async def check() -> None:
        entered_provider = asyncio.Event()

        async def wait_for_cancellation(_request: ModelRequest) -> ModelResponse:
            entered_provider.set()
            await asyncio.Event().wait()
            return _text()

        orchestrator, config, provider, _ = _setup(
            tmp_path, wait_for_cancellation, request_timeout_seconds=10
        )
        task = asyncio.create_task(orchestrator.run(config))
        await entered_provider.wait()
        task.cancel()

        with pytest.raises(AgentRunCancelled) as cancelled:
            await task
        assert cancelled.value.result.outcome is OrchestrationOutcome.CANCELLED
        assert cancelled.value.result.run.status is RunStatus.CANCELLED
        assert len(provider.requests) == 1

    asyncio.run(check())


def test_duplicate_call_ids_do_not_authorize_second_proposal(tmp_path: Path) -> None:
    (tmp_path / "src" / "file.py").parent.mkdir()
    (tmp_path / "src" / "file.py").write_text("safe", encoding="utf-8")
    orchestrator, config, _, _ = _setup(
        tmp_path,
        _tool_response(_call("same"), _call("same")),
        max_tool_calls_per_response=2,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.proposal_decisions[0].outcome is ProposalOutcome.AUTHORIZED_NOT_EXECUTED
    assert result.proposal_decisions[1].validation_error is ToolRegistryErrorCode.DUPLICATE_CALL_ID
    assert result.proposal_decisions[1].policy_decision is None


def test_tool_response_never_causes_provider_continuation(tmp_path: Path) -> None:
    target = tmp_path / "src" / "file.py"
    target.parent.mkdir()
    target.write_text("safe", encoding="utf-8")
    provider = MockModelProvider((_tool_response(_call()), _text("must not be requested")))
    definition = ToolDefinition(
        "read_file",
        "Read one synthetic file.",
        ReadArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
        resource_fields=("path",),
    )
    registry = ToolRegistry((definition,))
    context = AuthorizationContext(
        str(RUN_ID),
        tmp_path,
        ExecutionWorkspace.SOURCE,
        "baseline",
        frozenset({Capability.REPOSITORY_READ}),
    )
    orchestrator = AgentOrchestrator(
        provider=provider,
        registry=registry,
        policy_engine=DefaultPolicyEngine(registry),
        clock=lambda: NOW,
    )
    config = AgentLoopConfig("Task.", MODEL, RUN_ID, context, tmp_path)

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.AWAITING_EXECUTION
    assert provider.invocation_count == 1


def test_invalid_provider_response_fails_without_exposing_output(tmp_path: Path) -> None:
    orchestrator, config, _, _ = _setup(tmp_path, object())

    result = asyncio.run(orchestrator.run(config))

    assert result.run.status is RunStatus.FAILED
    assert result.error_code is OrchestrationErrorCode.INVALID_PROVIDER_RESPONSE
    assert result.response_summary is None


def test_event_history_is_ordered_bounded_and_content_minimized(tmp_path: Path) -> None:
    response = _tool_response(_call())
    orchestrator, config, _, _ = _setup(tmp_path, response)
    config = AgentLoopConfig(
        task="do not copy this prompt",
        model=config.model,
        run_id=config.run_id,
        authorization=config.authorization,
        workspace=config.workspace,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.events[0].event_type is AgentEventType.RUN_STARTED
    assert result.events[-1].event_type is AgentEventType.RUN_TERMINATED
    assert all(event.sequence == index for index, event in enumerate(result.events, start=1))
    assert len(result.events) <= 2 * config.max_tool_calls_per_response + 8
    assert "do not copy this prompt" not in repr(result.events)
    assert all(not hasattr(event, "response_text") for event in result.events)


def test_runtime_budget_caps_requests_even_when_reusable_defaults_are_higher(
    tmp_path: Path,
) -> None:
    orchestrator, config, provider, _ = _setup(
        tmp_path,
        _text(),
        budget_limits=BudgetConfig(max_model_requests=30),
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.model_requests == 1
    assert result.budget_snapshot.limits.max_model_requests == 1
    assert provider.requests[0].timeout_seconds <= config.request_timeout_seconds


def test_runtime_budget_applies_configured_reported_usage_limit_before_handling_response(
    tmp_path: Path,
) -> None:
    orchestrator, config, _, _ = _setup(
        tmp_path,
        _text("private response body", TokenUsage(3, 6)),
        budget_limits=BudgetConfig(max_reported_output_tokens=5),
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.LIMIT_EXCEEDED
    assert result.run.status is RunStatus.PARTIAL
    assert result.error_code is OrchestrationErrorCode.REPORTED_OUTPUT_TOKEN_LIMIT
    assert result.budget_reason_code is BudgetReasonCode.REPORTED_OUTPUT_TOKENS
    assert result.budget_snapshot.usage.output_tokens == 6
    assert result.response_summary is None
    assert "private response body" not in repr(result)


def test_loop_stops_when_cumulative_proposal_budget_is_exceeded(tmp_path: Path) -> None:
    response = _tool_response(_call("one", "a.py"), _call("two", "b.py"))
    orchestrator, config, _, _ = _setup(
        tmp_path,
        response,
        max_tool_calls_per_response=2,
        budget_limits=BudgetConfig(max_total_tool_calls=1),
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.LIMIT_EXCEEDED
    assert result.run.status is RunStatus.PARTIAL
    assert result.error_code is OrchestrationErrorCode.TOTAL_TOOL_CALL_LIMIT
    assert result.budget_reason_code is BudgetReasonCode.TOTAL_TOOL_CALLS
    assert result.budget_snapshot.tool_call_proposals == 2
    assert result.proposal_decisions == ()


def test_unknown_usage_remains_unknown_and_zero_usage_is_recorded(tmp_path: Path) -> None:
    orchestrator, config, _, _ = _setup(tmp_path, _text(usage=TokenUsage(0, 0)))

    result = asyncio.run(orchestrator.run(config))

    assert result.budget_snapshot.usage.input_tokens == 0
    assert result.budget_snapshot.usage.output_tokens == 0
    assert result.budget_snapshot.usage.reports == 1


def test_invalid_provider_usage_fails_safely_without_counting_it(tmp_path: Path) -> None:
    orchestrator, config, _, _ = _setup(
        tmp_path,
        _text("private response body", TokenUsage(1 << 64, 0)),
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.PROVIDER_ERROR
    assert result.run.status is RunStatus.FAILED
    assert result.error_code is OrchestrationErrorCode.INVALID_PROVIDER_RESPONSE
    assert result.budget_snapshot.usage.reports == 0
    assert "private response body" not in repr(result)


def test_deadline_shortens_provider_timeout_and_prevents_late_start(tmp_path: Path) -> None:
    now = [100.0, 100.75, 100.75]

    def clock() -> float:
        return now.pop(0) if now else 100.75

    orchestrator, config, provider, _ = _setup(
        tmp_path,
        _text(),
        monotonic=clock,
        request_timeout_seconds=0.9,
        run_timeout_seconds=1,
    )

    result = asyncio.run(orchestrator.run(config))

    assert result.outcome is OrchestrationOutcome.TEXT_RESPONSE
    assert provider.requests[0].timeout_seconds == pytest.approx(0.25)

    now = [0.0, 1.0]
    orchestrator, config, provider, _ = _setup(
        tmp_path,
        _text(),
        monotonic=lambda: now.pop(0) if now else 1.0,
        run_timeout_seconds=1,
    )
    result = asyncio.run(orchestrator.run(config))
    assert result.error_code is OrchestrationErrorCode.RUN_DEADLINE_EXCEEDED
    assert provider.requests == []


def test_cancel_before_provider_start_propagates_with_zero_requests(tmp_path: Path) -> None:
    async def check() -> None:
        orchestrator, config, provider, _ = _setup(tmp_path, _text())
        task = asyncio.create_task(orchestrator.run(config))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(AgentRunCancelled) as cancelled:
            await task
        assert cancelled.value.result.run.status is RunStatus.CANCELLED
        assert cancelled.value.result.model_requests == 0
        assert provider.requests == []

    asyncio.run(check())


def test_event_count_and_encoded_size_caps_report_dropped_events(tmp_path: Path) -> None:
    orchestrator, config, _, _ = _setup(tmp_path, _text(), max_events=2)

    result = asyncio.run(orchestrator.run(config))

    assert len(result.events) == 2
    assert result.events_dropped > 0
    assert [event.sequence for event in result.events] == [1, 2]

    orchestrator, config, _, _ = _setup(tmp_path, _text(), max_event_bytes=0)
    result = asyncio.run(orchestrator.run(config))
    assert result.events == ()
    assert result.events_dropped > 0
    assert result.event_bytes == 0
