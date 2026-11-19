"""Tests for provider-neutral request and response contracts."""

from collections.abc import Callable

import pytest

from repopilot.agent.contracts import ToolCall
from repopilot.providers.base import (
    FinishReason,
    InvalidProviderResponseError,
    ModelIdentifier,
    ModelMessage,
    ModelRequest,
    ModelRole,
    ProviderPermanentError,
    TextResponse,
    TokenUsage,
    ToolCallResponse,
)

pytestmark = pytest.mark.unit

MODEL = ModelIdentifier(provider_id="mock", model_id="test-model")


def test_text_response_has_stable_tag_model_and_optional_usage() -> None:
    response = TextResponse(
        model=MODEL,
        text="Ready.",
        finish_reason=FinishReason.STOP,
    )

    assert response.kind == "text"
    assert response.model == MODEL
    assert response.text == "Ready."
    assert response.usage is None


def test_tool_response_supports_multiple_proposed_calls() -> None:
    calls = (
        ToolCall(id="call-1", name="read_file", arguments={"path": "a.py"}),
        ToolCall(id="call-2", name="search", arguments={"query": "symbol"}),
    )
    response = ToolCallResponse(
        model=MODEL,
        tool_calls=calls,
        finish_reason=FinishReason.TOOL_CALLS,
        usage=TokenUsage(input_tokens=12, output_tokens=4),
    )

    assert response.kind == "tool_calls"
    assert response.tool_calls == calls
    assert response.usage == TokenUsage(input_tokens=12, output_tokens=4)


def test_usage_accepts_partial_provider_metadata() -> None:
    assert TokenUsage(input_tokens=12, output_tokens=None).input_tokens == 12
    assert TokenUsage(input_tokens=None, output_tokens=4).output_tokens == 4


@pytest.mark.parametrize(
    "timeout_seconds",
    [0, -1, float("nan"), float("inf"), "1"],
)
def test_request_rejects_invalid_timeout(timeout_seconds: object) -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        ModelRequest(model=MODEL, messages=(), timeout_seconds=timeout_seconds)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: TextResponse(model=MODEL, text="", finish_reason=FinishReason.STOP),
        lambda: TextResponse(model=MODEL, text="  ", finish_reason=FinishReason.STOP),
        lambda: ToolCallResponse(model=MODEL, tool_calls=(), finish_reason=FinishReason.TOOL_CALLS),
        lambda: ToolCallResponse(
            model=MODEL,
            tool_calls=(object(),),
            finish_reason=FinishReason.TOOL_CALLS,
        ),
    ],
)
def test_empty_or_malformed_provider_responses_are_rejected(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(InvalidProviderResponseError):
        factory()


def test_model_request_uses_explicit_roles_and_timeout() -> None:
    message = ModelMessage(role=ModelRole.USER, content="Inspect this repository.")
    request = ModelRequest(model=MODEL, messages=(message,), timeout_seconds=2.5)

    assert request.model == MODEL
    assert request.messages == (message,)
    assert request.timeout_seconds == 2.5


def test_permanent_provider_error_is_not_retryable() -> None:
    assert ProviderPermanentError().retryable is False
