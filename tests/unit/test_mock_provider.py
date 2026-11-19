"""Deterministic, offline tests for the mock model provider."""

import asyncio

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.providers.base import (
    FinishReason,
    InvalidProviderResponseError,
    ModelIdentifier,
    ModelMessage,
    ModelProviderError,
    ModelRequest,
    ModelRole,
    ProviderAuthenticationError,
    ProviderErrorCode,
    ProviderPermanentError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TextResponse,
    ToolCallResponse,
)
from repopilot.providers.mock import (
    MockModelProvider,
    MockProviderConcurrencyError,
    MockResponsesExhaustedError,
)

pytestmark = pytest.mark.unit

MODEL = ModelIdentifier(provider_id="mock", model_id="test-model")
REQUEST = ModelRequest(
    model=MODEL,
    messages=(ModelMessage(role=ModelRole.USER, content="private prompt material"),),
)
TEXT = TextResponse(model=MODEL, text="Ready.", finish_reason=FinishReason.STOP)
CALLS = ToolCallResponse(
    model=MODEL,
    tool_calls=(ToolCall(id="call-1", name="inspect", arguments={}),),
    finish_reason=FinishReason.TOOL_CALLS,
)


def test_mock_returns_scripted_text_and_tool_responses_in_order() -> None:
    provider = MockModelProvider((TEXT, CALLS))

    first = asyncio.run(provider.next_action(REQUEST))
    second = asyncio.run(provider.next_action(REQUEST))

    assert first is TEXT
    assert second is CALLS
    assert provider.invocation_count == 2


def test_mock_raises_typed_error_when_script_is_exhausted() -> None:
    provider = MockModelProvider((TEXT,))
    asyncio.run(provider.next_action(REQUEST))

    with pytest.raises(MockResponsesExhaustedError):
        asyncio.run(provider.next_action(REQUEST))


@pytest.mark.parametrize(
    ("error", "retryable", "code"),
    [
        (ProviderAuthenticationError(), False, ProviderErrorCode.AUTHENTICATION),
        (ProviderRateLimitError(), True, ProviderErrorCode.RATE_LIMITED),
        (ProviderTimeoutError(), True, ProviderErrorCode.TIMEOUT),
        (InvalidProviderResponseError(), False, ProviderErrorCode.INVALID_RESPONSE),
        (ProviderUnavailableError(), True, ProviderErrorCode.UNAVAILABLE),
        (ProviderPermanentError(), False, ProviderErrorCode.PERMANENT),
    ],
)
def test_mock_propagates_typed_provider_failures(
    error: ModelProviderError,
    retryable: bool,
    code: ProviderErrorCode,
) -> None:
    provider = MockModelProvider((error,))

    with pytest.raises(type(error)) as caught:
        asyncio.run(provider.next_action(REQUEST))

    assert caught.value.retryable is retryable
    assert caught.value.code is code


def test_request_history_keeps_metadata_but_not_prompt_content() -> None:
    provider = MockModelProvider((TEXT,))
    asyncio.run(provider.next_action(REQUEST))

    history = provider.request_history
    assert len(history) == 1
    assert history[0].model == MODEL
    assert history[0].message_roles == (ModelRole.USER,)
    assert history[0].message_lengths == (len("private prompt material"),)
    assert "private prompt material" not in repr(history)


def test_mock_instances_keep_invocations_and_history_isolated() -> None:
    first = MockModelProvider((TEXT,))
    second = MockModelProvider((CALLS,))

    assert asyncio.run(first.next_action(REQUEST)) is TEXT

    assert first.invocation_count == 1
    assert second.invocation_count == 0
    assert len(first.request_history) == 1
    assert second.request_history == ()


def test_mock_rejects_overlapping_calls_and_allows_cancellation() -> None:
    async def scenario() -> None:
        gate = asyncio.Event()
        provider = MockModelProvider((TEXT,), wait_before_response=gate)
        first_call = asyncio.create_task(provider.next_action(REQUEST))
        await asyncio.sleep(0)

        with pytest.raises(MockProviderConcurrencyError):
            await provider.next_action(REQUEST)

        first_call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_call

        gate.set()
        assert await provider.next_action(REQUEST) is TEXT
        assert provider.invocation_count == 3

    asyncio.run(scenario())


def test_mock_translates_request_timeout_to_provider_timeout() -> None:
    async def scenario() -> None:
        gate = asyncio.Event()
        provider = MockModelProvider((TEXT,), wait_before_response=gate)
        request = ModelRequest(model=MODEL, messages=(), timeout_seconds=0.01)

        with pytest.raises(ProviderTimeoutError):
            await provider.next_action(request)

    asyncio.run(scenario())
