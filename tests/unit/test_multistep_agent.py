from __future__ import annotations

import asyncio
import json
from uuid import UUID

import pytest

from repopilot.agent.budget import BudgetConfig
from repopilot.agent.contracts import ToolCall
from repopilot.agent.multistep import (
    MultiStepAgentOrchestrator,
    MultiStepConfig,
    MultiStepOutcome,
    MultiStepRunCancelled,
)
from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ModelRole,
    TextResponse,
    ToolCallResponse,
)
from repopilot.providers.mock import MockModelProvider
from repopilot.tools import create_readonly_tool_registry
from repopilot.tools.dispatcher import ToolExecutionResult, ToolExecutionStatus

MODEL = ModelIdentifier("mock", "offline-test")
RUN_ID = UUID("2c3b2299-6c61-4f8d-80c0-b10a6a1dc8b9")
READ_CALL = ToolCall("call-1", "repo_read_text", {"path": "pkg/example.py"})


class _Dispatcher:
    def __init__(self, *results: ToolExecutionResult) -> None:
        self.run_id = str(RUN_ID)
        self.results = list(results)
        self.calls: list[ToolCall] = []

    def dispatch(self, call: ToolCall) -> ToolExecutionResult:
        self.calls.append(call)
        return self.results.pop(0)


def _result(
    call_id: str = "call-1",
    *,
    status: ToolExecutionStatus = ToolExecutionStatus.SUCCESS,
    payload: str | None = '{"text":"actual source"}',
    reason: str | None = None,
    executed: bool = True,
    truncated: bool = False,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        call_id=call_id,
        tool_name="repo_read_text",
        status=status,
        executed=executed,
        reason_code=reason,
        truncated=truncated,
        payload_size_bytes=0 if payload is None else len(payload.encode("utf-8")),
        duration_ms=1,
        payload_json=payload,
    )


def _orchestrator(provider: MockModelProvider, dispatcher: _Dispatcher):
    return MultiStepAgentOrchestrator(
        provider=provider,
        registry=create_readonly_tool_registry(),
        dispatcher=dispatcher,  # type: ignore[arg-type]
    )


def _config(**kwargs: object) -> MultiStepConfig:
    allow_feedback = kwargs.pop("allow_repository_feedback", True)
    return MultiStepConfig(
        task="Inspect the parser.",
        model=MODEL,
        run_id=RUN_ID,
        allow_repository_feedback=allow_feedback,
        **kwargs,
    )


def _tools(*calls: ToolCall) -> ToolCallResponse:
    return ToolCallResponse(MODEL, calls, FinishReason.TOOL_CALLS)


def _text(value: str = "Inspection is complete.") -> TextResponse:
    return TextResponse(MODEL, value, FinishReason.STOP)


def test_two_decisions_feed_back_actual_correlated_tool_result() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text()))
    dispatcher = _Dispatcher(_result())

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert result.outcome is MultiStepOutcome.TEXT_RESPONSE
    assert result.run.status.value == "PARTIAL"
    assert not result.run.verified
    assert len(provider.request_history) == 2
    assert dispatcher.calls == [READ_CALL]
    second_request_messages = provider.request_history[1].message_roles
    assert second_request_messages[-1] is ModelRole.TOOL
    assert result.tool_results[0].call_id == READ_CALL.id
    feedback = json.loads(result.tool_results[0].output)
    assert feedback["status"] == "success"
    assert feedback["executed"] is True
    assert feedback["payload"]["text"] == "actual source"


def test_tool_feedback_is_correlated_and_keeps_response_order() -> None:
    first = READ_CALL
    second = ToolCall("call-2", "repo_read_text", {"path": "pkg/other.py"})
    provider = MockModelProvider((_tools(first, second), _text()))
    dispatcher = _Dispatcher(_result("call-1"), _result("call-2"))

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert [item.call_id for item in result.tool_results] == ["call-1", "call-2"]
    assert [call.id for call in dispatcher.calls] == ["call-1", "call-2"]


def test_denial_is_reported_and_stops_without_another_model_request() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text("must not be requested")))
    dispatcher = _Dispatcher(
        _result(
            status=ToolExecutionStatus.POLICY_DENIED,
            payload=None,
            reason="capability_denied",
            executed=False,
        )
    )

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert result.outcome is MultiStepOutcome.TOOL_EXECUTION_FAILED
    assert result.run.status.value == "BLOCKED"
    assert len(provider.request_history) == 1
    feedback = json.loads(result.tool_results[0].output)
    assert feedback["status"] == "policy_denied"
    assert feedback["executed"] is False
    assert feedback["reason_code"] == "capability_denied"


def test_approval_required_result_is_never_retried_or_treated_as_execution() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text("must not be requested")))
    dispatcher = _Dispatcher(
        _result(
            status=ToolExecutionStatus.APPROVAL_REQUIRED,
            payload=None,
            reason="approval_required",
            executed=False,
        )
    )

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert result.outcome is MultiStepOutcome.APPROVAL_REQUIRED
    assert result.run.status.value == "AWAITING_APPROVAL"
    assert result.error_code.value == "approval_required"
    assert len(provider.request_history) == 1
    assert not result.tool_results[0].ok
    assert json.loads(result.tool_results[0].output)["executed"] is False


@pytest.mark.parametrize(
    "calls",
    [
        (ToolCall("bad", "unknown_tool", {}),),
        (ToolCall("same", "repo_read_text", {"path": "a.py"}),) * 2,
        (ToolCall("missing", "repo_read_text", {}),),
    ],
)
def test_invalid_or_duplicate_proposals_never_reach_dispatcher(
    calls: tuple[ToolCall, ...],
) -> None:
    provider = MockModelProvider((_tools(*calls), _text()))
    dispatcher = _Dispatcher()

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert result.outcome is MultiStepOutcome.INVALID_TOOL_CALL
    assert dispatcher.calls == []
    assert len(provider.request_history) == 1


def test_noncontinuing_provider_never_receives_tool_feedback() -> None:
    class OneDecisionProvider(MockModelProvider):
        supports_conversation_continuation = False

    provider = OneDecisionProvider((_tools(READ_CALL), _text("must not be requested")))
    dispatcher = _Dispatcher(_result())

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert result.outcome is MultiStepOutcome.CONTINUATION_UNSUPPORTED
    assert result.run.status.value == "PARTIAL"
    assert len(provider.request_history) == 1
    assert dispatcher.calls == [READ_CALL]


def test_repository_feedback_is_off_by_default() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text("must not be requested")))
    dispatcher = _Dispatcher(_result())

    result = asyncio.run(
        _orchestrator(provider, dispatcher).run(
            MultiStepConfig("Inspect the parser.", MODEL, RUN_ID)
        )
    )

    assert result.outcome is MultiStepOutcome.CONTINUATION_UNSUPPORTED
    assert result.error_code.value == "repository_feedback_disabled"
    assert len(provider.request_history) == 1
    assert dispatcher.calls == [READ_CALL]


def test_provider_without_repository_feedback_support_gets_no_tool_payload() -> None:
    class NoRepositoryFeedbackProvider(MockModelProvider):
        allows_repository_feedback = False

    provider = NoRepositoryFeedbackProvider((_tools(READ_CALL), _text("must not be requested")))
    dispatcher = _Dispatcher(_result(payload=json.dumps({"text": "private fixture content"})))

    result = asyncio.run(
        _orchestrator(provider, dispatcher).run(_config(allow_repository_feedback=True))
    )

    assert result.error_code.value == "repository_feedback_disabled"
    assert len(provider.request_history) == 1
    assert dispatcher.calls == [READ_CALL]


def test_tool_proposal_budget_is_cumulative() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _tools(READ_CALL)))
    dispatcher = _Dispatcher(_result())
    budget = BudgetConfig(
        max_model_requests=3,
        max_run_seconds=30,
        max_tool_calls_per_response=2,
        max_total_tool_calls=1,
    )

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config(budget_limits=budget)))

    assert result.outcome is MultiStepOutcome.LIMIT_EXCEEDED
    assert len(provider.request_history) == 2
    assert len(dispatcher.calls) == 1


def test_model_request_limit_stops_repeated_tool_proposals() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _tools(READ_CALL), _text()))
    dispatcher = _Dispatcher(_result(), _result())
    budget = BudgetConfig(
        max_model_requests=2,
        max_run_seconds=30,
        max_tool_calls_per_response=2,
        max_total_tool_calls=4,
    )

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config(budget_limits=budget)))

    assert result.outcome is MultiStepOutcome.LIMIT_EXCEEDED
    assert result.budget_reason_code.value == "model_request_limit"
    assert len(provider.request_history) == 2
    assert len(dispatcher.calls) == 2


def test_feedback_is_bounded_and_marks_payload_omission() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text()))
    large_payload = json.dumps({"text": "x" * 2_000})
    dispatcher = _Dispatcher(_result(payload=large_payload))

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config(max_feedback_bytes=512)))

    feedback = json.loads(result.tool_results[0].output)
    assert result.tool_results[0].truncated
    assert feedback["payload"] is None
    assert feedback["payload_omitted"] is True
    assert len(result.tool_results[0].output.encode("utf-8")) <= 512
    assert len(provider.request_history) == 2


def test_cumulative_feedback_limit_stops_before_an_unrecordable_read() -> None:
    first = READ_CALL
    second = ToolCall("call-2", "repo_read_text", {"path": "pkg/other.py"})
    provider = MockModelProvider((_tools(first, second), _text()))
    dispatcher = _Dispatcher(
        _result("call-1", payload=json.dumps({"text": "x" * 60})),
        _result("call-2"),
    )

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config(max_feedback_bytes=400)))

    assert result.outcome is MultiStepOutcome.LIMIT_EXCEEDED
    assert result.error_code.value == "feedback_limit"
    assert [call.id for call in dispatcher.calls] == ["call-1"]
    assert [item.call_id for item in result.tool_results] == ["call-1"]


def test_conversation_limit_blocks_provider_request() -> None:
    provider = MockModelProvider((_text(),))
    dispatcher = _Dispatcher()

    result = asyncio.run(
        _orchestrator(provider, dispatcher).run(_config(max_conversation_bytes=512))
    )

    assert result.outcome is MultiStepOutcome.LIMIT_EXCEEDED
    assert result.error_code.value == "conversation_limit"
    assert provider.invocation_count == 0


def test_provider_timeout_is_reported_without_retry() -> None:
    async def run_timeout() -> None:
        provider = MockModelProvider((_text(),), wait_before_response=asyncio.Event())
        dispatcher = _Dispatcher()
        config = _config(request_timeout_seconds=0.01)

        result = await _orchestrator(provider, dispatcher).run(config)

        assert result.outcome is MultiStepOutcome.PROVIDER_ERROR
        assert result.error_code.value == "provider_timeout"
        assert provider.invocation_count == 1
        assert dispatcher.calls == []

    asyncio.run(run_timeout())


def test_overall_deadline_is_reported_separately_from_provider_timeout() -> None:
    class DeadlineProvider:
        supports_conversation_continuation = True
        allows_repository_feedback = True

        async def next_action(self, request):
            await asyncio.sleep(request.timeout_seconds + 0.05)
            return _text()

    provider = DeadlineProvider()
    budget = BudgetConfig(
        max_model_requests=2,
        max_run_seconds=0.01,
        max_tool_calls_per_response=2,
        max_total_tool_calls=2,
    )
    orchestrator = MultiStepAgentOrchestrator(
        provider=provider,  # type: ignore[arg-type]
        registry=create_readonly_tool_registry(),
        dispatcher=_Dispatcher(),  # type: ignore[arg-type]
    )

    result = asyncio.run(orchestrator.run(_config(budget_limits=budget, request_timeout_seconds=1)))

    assert result.outcome is MultiStepOutcome.LIMIT_EXCEEDED
    assert result.budget_reason_code.value == "run_deadline_exceeded"


def test_only_registered_read_tools_are_exposed() -> None:
    provider = MockModelProvider((_text(),))
    dispatcher = _Dispatcher()
    orchestrator = _orchestrator(provider, dispatcher)

    assert orchestrator._registry.names == (
        "repo_discover_files",
        "repo_read_text",
        "repo_search_literal",
        "repo_index_python",
    )
    assert not any("shell" in name or "docker" in name for name in orchestrator._registry.names)


def test_run_events_are_ordered_and_do_not_store_read_contents() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text()))
    dispatcher = _Dispatcher(_result(payload=json.dumps({"text": "secret fixture text"})))

    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert [event.sequence for event in result.events] == sorted(
        event.sequence for event in result.events
    )
    assert "secret fixture text" not in repr(result.events)
    assert result.run.verification_evidence is None


def test_cancelled_model_request_returns_terminal_cancelled_snapshot() -> None:
    async def run_cancelled() -> None:
        gate = asyncio.Event()
        provider = MockModelProvider((_text(),), wait_before_response=gate)
        dispatcher = _Dispatcher()
        task = asyncio.create_task(_orchestrator(provider, dispatcher).run(_config()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(MultiStepRunCancelled) as caught:
            await task
        assert caught.value.result.run.status.value == "CANCELLED"
        assert dispatcher.calls == []

    asyncio.run(run_cancelled())


def test_openai_continuation_contract_is_explicitly_unsupported() -> None:
    from repopilot.providers.adapters.openai import OpenAIModelProvider

    # Construct without initializing the SDK client: capability is static adapter metadata.
    provider = object.__new__(OpenAIModelProvider)
    assert provider.supports_conversation_continuation is False
    assert provider.allows_repository_feedback is False


def test_provider_request_contains_untrusted_tool_role_feedback_only() -> None:
    provider = MockModelProvider((_tools(READ_CALL), _text()))
    dispatcher = _Dispatcher(_result())
    result = asyncio.run(_orchestrator(provider, dispatcher).run(_config()))

    assert result.tool_results[0].ok
    assert provider.request_history[1].message_roles[-1] is ModelRole.TOOL
    assert all(
        role in {ModelRole.SYSTEM, ModelRole.USER, ModelRole.ASSISTANT, ModelRole.TOOL}
        for role in provider.request_history[1].message_roles
    )
