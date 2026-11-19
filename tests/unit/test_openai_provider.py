"""Offline tests for the OpenAI Responses API adapter."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import SimpleNamespace
from typing import cast

import httpx2
import openai
import pytest
from openai import AsyncOpenAI
from openai.types.responses import Response

from repopilot.agent.contracts import ToolCall
from repopilot.providers.adapters.openai import (
    OpenAICredentialsMissingError,
    OpenAIModelProvider,
)
from repopilot.providers.base import (
    FinishReason,
    InvalidProviderResponseError,
    ModelIdentifier,
    ModelMessage,
    ModelProvider,
    ModelRequest,
    ModelRole,
    ProviderAuthenticationError,
    ProviderPermanentError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TextResponse,
    TokenUsage,
    ToolCallResponse,
)

pytestmark = pytest.mark.unit

MODEL = ModelIdentifier(provider_id="openai", model_id="gpt-test")
TOOL = {"name": "inspect", "parameters": {"type": "object", "properties": {}}}


def _item(type_: str, **values: object) -> SimpleNamespace:
    return SimpleNamespace(type=type_, **values)


def _response(
    *output: object,
    usage: object = None,
    model: str = "gpt-test",
    status: str = "completed",
    incomplete_details: object = None,
) -> Response:
    return Response.model_construct(
        status=status,
        output=list(output),
        usage=usage,
        model=model,
        incomplete_details=incomplete_details,
    )


def _message(*parts: object, role: str = "assistant") -> SimpleNamespace:
    return _item("message", role=role, content=list(parts))


class _Responses:
    def __init__(self, outcome: object) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, object]] = []

    async def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class _Client:
    def __init__(self, outcome: object) -> None:
        self.responses = _Responses(outcome)
        self.options: list[dict[str, object]] = []

    def with_options(self, **kwargs: object) -> _Client:
        self.options.append(kwargs)
        return self


def _provider(outcome: object) -> tuple[OpenAIModelProvider, _Client]:
    client = _Client(outcome)
    return OpenAIModelProvider(client=cast(AsyncOpenAI, client)), client


def _request(
    *,
    messages: tuple[ModelMessage, ...] = (ModelMessage(ModelRole.USER, "hello"),),
    tools: tuple[Mapping[str, object], ...] = (),
    model: ModelIdentifier = MODEL,
    timeout_seconds: float = 3.0,
) -> ModelRequest:
    return ModelRequest(
        model=model,
        messages=messages,
        tools=tools,
        timeout_seconds=timeout_seconds,
    )


def test_text_response_maps_model_usage_and_request_settings() -> None:
    response = _response(
        _message(_item("output_text", text="hello back")),
        usage=SimpleNamespace(input_tokens=12, output_tokens=3),
    )
    provider, client = _provider(response)

    result = asyncio.run(provider.next_action(_request(timeout_seconds=2.5)))

    assert isinstance(result, TextResponse)
    assert result.model == MODEL
    assert result.text == "hello back"
    assert result.finish_reason is FinishReason.STOP
    assert result.usage == TokenUsage(input_tokens=12, output_tokens=3)
    assert client.options == [{"max_retries": 0}]
    assert client.responses.calls[0]["model"] == "gpt-test"
    assert client.responses.calls[0]["timeout"] == 2.5


def test_missing_usage_stays_unavailable() -> None:
    provider, _ = _provider(_response(_message(_item("output_text", text="ready"))))

    result = asyncio.run(provider.next_action(_request()))

    assert isinstance(result, TextResponse)
    assert result.usage is None


def test_single_and_multiple_function_calls_preserve_ids_and_arguments() -> None:
    outputs = [
        _item("function_call", call_id="call-1", name="inspect", arguments='{"x": 1}'),
        _item("function_call", call_id="call-2", name="inspect", arguments='{"x": 2}'),
    ]
    single_provider, _ = _provider(_response(outputs[0]))
    single = asyncio.run(single_provider.next_action(_request(tools=(TOOL,))))
    assert isinstance(single, ToolCallResponse)
    assert single.tool_calls == (ToolCall(id="call-1", name="inspect", arguments={"x": 1}),)

    provider, _ = _provider(_response(*outputs))

    result = asyncio.run(provider.next_action(_request(tools=(TOOL,))))

    assert isinstance(result, ToolCallResponse)
    assert result.finish_reason is FinishReason.TOOL_CALLS
    assert result.tool_calls == (
        ToolCall(id="call-1", name="inspect", arguments={"x": 1}),
        ToolCall(id="call-2", name="inspect", arguments={"x": 2}),
    )


def test_translates_messages_tool_results_and_function_schemas() -> None:
    messages = (
        ModelMessage(ModelRole.SYSTEM, "rules"),
        ModelMessage(ModelRole.DEVELOPER, "details"),
        ModelMessage(ModelRole.USER, "inspect"),
        ModelMessage(
            ModelRole.ASSISTANT,
            "",
            tool_calls=(ToolCall("call-7", "inspect", {"path": "a.py"}),),
        ),
        ModelMessage(ModelRole.TOOL, "done", tool_call_id="call-7"),
        ModelMessage(ModelRole.ASSISTANT, "finished"),
    )
    provider, client = _provider(_response(_message(_item("output_text", text="next"))))

    asyncio.run(provider.next_action(_request(messages=messages, tools=(TOOL,))))

    assert client.responses.calls[0]["input"] == [
        {"type": "message", "role": "system", "content": "rules"},
        {"type": "message", "role": "developer", "content": "details"},
        {"type": "message", "role": "user", "content": "inspect"},
        {
            "type": "function_call",
            "call_id": "call-7",
            "name": "inspect",
            "arguments": '{"path":"a.py"}',
        },
        {"type": "function_call_output", "call_id": "call-7", "output": "done"},
        {"type": "message", "role": "assistant", "content": "finished"},
    ]
    assert client.responses.calls[0]["tools"] == [{"type": "function", **TOOL}]


@pytest.mark.parametrize(
    "call",
    [
        _item("function_call", call_id="call-1", name="inspect", arguments="[]"),
        _item("function_call", call_id="call-1", name="inspect", arguments="not json"),
        _item("function_call", call_id="call-1", name="inspect", arguments='{"x":1,"x":2}'),
        _item("function_call", name="inspect", arguments="{}"),
        _item("function_call", call_id="", name="inspect", arguments="{}"),
        _item("function_call", call_id="call-1", name="", arguments="{}"),
    ],
)
def test_rejects_malformed_or_ambiguous_tool_calls(call: object) -> None:
    provider, _ = _provider(_response(call))
    with pytest.raises(InvalidProviderResponseError):
        asyncio.run(provider.next_action(_request(tools=(TOOL,))))


def test_rejects_duplicate_call_ids_and_unadvertised_tool_names() -> None:
    duplicate = _item("function_call", call_id="same", name="inspect", arguments="{}")
    provider, _ = _provider(_response(duplicate, duplicate))
    with pytest.raises(InvalidProviderResponseError):
        asyncio.run(provider.next_action(_request(tools=(TOOL,))))


def test_invalid_tool_schemas_fail_before_the_sdk_call() -> None:
    provider, client = _provider(_response(_message(_item("output_text", text="ok"))))
    invalid_schemas: tuple[Mapping[str, object], ...] = (
        {"name": "inspect", "parameters": {"type": "array"}},
        {"name": "inspect", "parameters": {"type": "object", "properties": []}},
        {"name": "inspect", "parameters": {"type": "object", "extra": object()}},
    )
    for schema in invalid_schemas:
        with pytest.raises(ProviderPermanentError):
            asyncio.run(provider.next_action(_request(tools=(schema,))))
    assert client.responses.calls == []


def test_ambiguous_assistant_text_and_call_history_is_rejected() -> None:
    provider, client = _provider(_response(_message(_item("output_text", text="ok"))))
    message = ModelMessage(
        ModelRole.ASSISTANT,
        "text ordering is ambiguous",
        tool_calls=(ToolCall("call-1", "inspect", {}),),
    )

    with pytest.raises(ProviderPermanentError):
        asyncio.run(provider.next_action(_request(messages=(message,), tools=(TOOL,))))
    assert client.responses.calls == []

    unknown = _item("function_call", call_id="call-1", name="delete", arguments="{}")
    provider, _ = _provider(_response(unknown))
    with pytest.raises(InvalidProviderResponseError):
        asyncio.run(provider.next_action(_request(tools=(TOOL,))))


@pytest.mark.parametrize(
    "response",
    [
        _response(_message(_item("output_text", text="  "))),
        _response(_item("reasoning", summary=[]), _message(_item("output_text", text="hi"))),
        _response(_item("web_search_call", id="ws-1")),
        _response(_message(_item("refusal", refusal="no"))),
        _response(
            _item(
                "message",
                status="incomplete",
                role="assistant",
                content=[_item("output_text", text="partial")],
            )
        ),
        _response(status="incomplete"),
        _response(status="failed"),
        _response(),
        _response(
            _message(_item("output_text", text="text")),
            _item("function_call", call_id="call", name="inspect", arguments="{}"),
        ),
        _response(_message(_item("output_text", text="incomplete")), incomplete_details={}),
        _response(_message(_item("output_text", text="ok")), model=""),
        _response(
            _message(_item("output_text", text="ok")),
            usage=SimpleNamespace(input_tokens=-1, output_tokens=1),
        ),
        object(),
    ],
)
def test_rejects_incomplete_unsupported_and_mixed_outputs(response: object) -> None:
    provider, _ = _provider(response)
    with pytest.raises(InvalidProviderResponseError):
        asyncio.run(provider.next_action(_request(tools=(TOOL,))))


def test_invalid_provider_identifier_fails_before_sdk_call() -> None:
    provider, client = _provider(_response(_message(_item("output_text", text="ok"))))

    with pytest.raises(ProviderPermanentError):
        asyncio.run(
            provider.next_action(
                _request(model=ModelIdentifier(provider_id="other", model_id="gpt-test"))
            )
        )

    assert client.responses.calls == []


def test_unmatched_or_duplicate_tool_results_are_rejected() -> None:
    provider, _ = _provider(_response(_message(_item("output_text", text="ok"))))
    with pytest.raises(ProviderPermanentError):
        asyncio.run(
            provider.next_action(
                _request(messages=(ModelMessage(ModelRole.TOOL, "x", tool_call_id="missing"),))
            )
        )

    call = ToolCall("call-1", "inspect", {})
    messages = (
        ModelMessage(ModelRole.ASSISTANT, "", tool_calls=(call,)),
        ModelMessage(ModelRole.TOOL, "first", tool_call_id="call-1"),
        ModelMessage(ModelRole.TOOL, "second", tool_call_id="call-1"),
    )
    with pytest.raises(ProviderPermanentError):
        asyncio.run(provider.next_action(_request(messages=messages)))


def test_api_exceptions_are_mapped_to_safe_typed_errors() -> None:
    request = httpx2.Request("POST", "https://api.openai.com/v1/responses")
    auth_response = httpx2.Response(401, request=request)
    rate_response = httpx2.Response(429, request=request)
    bad_request = httpx2.Response(400, request=request)
    timeout_response = httpx2.Response(408, request=request)
    server_error = httpx2.Response(500, request=request)
    invalid_response = openai.APIResponseValidationError(
        httpx2.Response(200, request=request), body={}
    )
    cases = [
        (
            openai.AuthenticationError("secret detail", response=auth_response, body=None),
            ProviderAuthenticationError,
        ),
        (
            openai.RateLimitError("secret detail", response=rate_response, body=None),
            ProviderRateLimitError,
        ),
        (openai.APITimeoutError(request=request), ProviderTimeoutError),
        (openai.APIConnectionError(request=request), ProviderUnavailableError),
        (
            openai.BadRequestError("secret detail", response=bad_request, body=None),
            ProviderPermanentError,
        ),
        (
            openai.APIStatusError("secret detail", response=timeout_response, body=None),
            ProviderTimeoutError,
        ),
        (
            openai.InternalServerError("secret detail", response=server_error, body=None),
            ProviderUnavailableError,
        ),
        (invalid_response, InvalidProviderResponseError),
    ]
    for error, expected in cases:
        provider, _ = _provider(error)
        with pytest.raises(expected) as caught:
            asyncio.run(provider.next_action(_request()))
        assert "secret detail" not in str(caught.value)


def test_cancellation_propagates_and_no_retry_is_configured() -> None:
    class _WaitingResponses(_Responses):
        async def create(self, **kwargs: object) -> object:
            self.calls.append(kwargs)
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    client = _Client(_response())
    client.responses = _WaitingResponses(None)
    provider = OpenAIModelProvider(client=cast(AsyncOpenAI, client))

    async def cancel() -> None:
        task = asyncio.create_task(provider.next_action(_request()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    assert client.options == [{"max_retries": 0}]


def test_missing_credentials_produce_safe_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(OpenAICredentialsMissingError) as caught:
        OpenAIModelProvider()

    assert "OPENAI_API_KEY" in str(caught.value)


def test_overall_deadline_translates_to_provider_timeout() -> None:
    class _WaitingResponses(_Responses):
        async def create(self, **kwargs: object) -> object:
            self.calls.append(kwargs)
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    client = _Client(_response())
    client.responses = _WaitingResponses(None)
    provider = OpenAIModelProvider(client=cast(AsyncOpenAI, client))

    with pytest.raises(ProviderTimeoutError):
        asyncio.run(provider.next_action(_request(timeout_seconds=0.01)))


def test_adapter_satisfies_model_provider_protocol() -> None:
    provider, _ = _provider(_response(_message(_item("output_text", text="ok"))))

    async def call(provider: ModelProvider) -> object:
        return await provider.next_action(_request())

    assert isinstance(asyncio.run(call(provider)), TextResponse)
