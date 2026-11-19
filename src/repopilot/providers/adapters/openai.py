"""OpenAI Responses API adapter for the provider-neutral model contracts."""

import asyncio
import json
from collections.abc import Mapping
from typing import cast

import openai
from openai import AsyncOpenAI
from openai.types.responses import FunctionToolParam, Response, ResponseInputParam

from repopilot.agent.contracts import ToolCall
from repopilot.providers.base import (
    FinishReason,
    InvalidProviderResponseError,
    ModelIdentifier,
    ModelMessage,
    ModelRequest,
    ModelResponse,
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

_PROVIDER_ID = "openai"


class OpenAICredentialsMissingError(ProviderAuthenticationError):
    """Missing SDK credentials with safe, actionable setup guidance."""

    safe_message = "Set OPENAI_API_KEY before using the OpenAI model provider."


class OpenAIModelProvider:
    """Make bounded, non-streaming Responses API calls without executing proposed tools."""

    def __init__(self, *, client: AsyncOpenAI | None = None) -> None:
        self._owns_client = client is None
        try:
            self._client = client if client is not None else AsyncOpenAI(max_retries=0)
        except openai.OpenAIError as error:
            raise OpenAICredentialsMissingError() from error

    async def close(self) -> None:
        """Close the SDK client only when this adapter created it."""
        if self._owns_client:
            await self._client.close()

    async def next_action(self, request: ModelRequest) -> ModelResponse:
        """Request one response, propagate cancellation, and expose only safe typed failures."""
        if request.model.provider_id != _PROVIDER_ID:
            raise ProviderPermanentError()
        input_items = _translate_messages(request.messages)
        tools = _translate_tools(request.tools)
        try:
            async with asyncio.timeout(request.timeout_seconds):
                response = await self._client.with_options(max_retries=0).responses.create(
                    model=request.model.model_id,
                    input=cast(ResponseInputParam, input_items),
                    tools=cast(list[FunctionToolParam], tools),
                    timeout=request.timeout_seconds,
                )
        except openai.AuthenticationError as error:
            raise ProviderAuthenticationError() from error
        except openai.RateLimitError as error:
            raise ProviderRateLimitError() from error
        except openai.APITimeoutError as error:
            raise ProviderTimeoutError() from error
        except openai.APIConnectionError as error:
            raise ProviderUnavailableError() from error
        except openai.APIResponseValidationError as error:
            raise InvalidProviderResponseError() from error
        except openai.APIStatusError as error:
            if error.status_code == 408:
                raise ProviderTimeoutError() from error
            if error.status_code >= 500:
                raise ProviderUnavailableError() from error
            raise ProviderPermanentError() from error
        except openai.APIError as error:
            raise ProviderPermanentError() from error
        except TimeoutError as error:
            raise ProviderTimeoutError() from error
        allowed_names = {name for tool in tools if isinstance((name := tool.get("name")), str)}
        return _normalize_response(response, allowed_names)


def _translate_messages(messages: tuple[ModelMessage, ...]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    seen_calls: set[str] = set()
    seen_results: set[str] = set()
    for message in messages:
        if message.role is ModelRole.TOOL:
            call_id = message.tool_call_id
            if (
                not isinstance(call_id, str)
                or not call_id.strip()
                or call_id not in seen_calls
                or call_id in seen_results
            ):
                raise ProviderPermanentError()
            if message.tool_calls:
                raise ProviderPermanentError()
            seen_results.add(call_id)
            items.append(
                {"type": "function_call_output", "call_id": call_id, "output": message.content}
            )
            continue
        if message.tool_call_id is not None:
            raise ProviderPermanentError()
        if message.role is not ModelRole.ASSISTANT and message.tool_calls:
            raise ProviderPermanentError()
        if message.role is ModelRole.ASSISTANT and message.tool_calls and message.content:
            raise ProviderPermanentError()
        if message.role is not ModelRole.ASSISTANT or message.content:
            items.append(
                {"type": "message", "role": message.role.value, "content": message.content}
            )
        for call in message.tool_calls:
            if (
                not isinstance(call.id, str)
                or not call.id.strip()
                or not isinstance(call.name, str)
                or not call.name.strip()
                or not isinstance(call.arguments, Mapping)
                or call.id in seen_calls
            ):
                raise ProviderPermanentError()
            try:
                arguments = json.dumps(
                    dict(call.arguments),
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
            except (TypeError, ValueError) as error:
                raise ProviderPermanentError() from error
            seen_calls.add(call.id)
            items.append(
                {
                    "type": "function_call",
                    "call_id": call.id,
                    "name": call.name,
                    "arguments": arguments,
                }
            )
    if not items:
        raise ProviderPermanentError()
    return items


def _translate_tools(tools: tuple[Mapping[str, object], ...]) -> list[dict[str, object]]:
    translated: list[dict[str, object]] = []
    names: set[str] = set()
    for tool in tools:
        if set(tool) - {"name", "description", "parameters", "strict"}:
            raise ProviderPermanentError()
        name = tool.get("name")
        parameters = tool.get("parameters")
        if (
            not isinstance(name, str)
            or not name.strip()
            or name in names
            or not isinstance(parameters, Mapping)
            or parameters.get("type") != "object"
            or (
                parameters.get("properties") is not None
                and not isinstance(parameters.get("properties"), Mapping)
            )
        ):
            raise ProviderPermanentError()
        description = tool.get("description")
        strict = tool.get("strict")
        if description is not None and not isinstance(description, str):
            raise ProviderPermanentError()
        if strict is not None and not isinstance(strict, bool):
            raise ProviderPermanentError()
        names.add(name)
        function_tool = {
            "type": "function",
            "name": name,
            **({"description": description} if description is not None else {}),
            "parameters": dict(parameters),
            **({"strict": strict} if strict is not None else {}),
        }
        try:
            json.dumps(function_tool, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ProviderPermanentError() from error
        translated.append(function_tool)
    return translated


def _normalize_response(response: object, allowed_tool_names: set[str]) -> ModelResponse:
    if (
        not isinstance(response, Response)
        or response.status != "completed"
        or response.incomplete_details is not None
    ):
        raise InvalidProviderResponseError()
    model_id = getattr(response, "model", None)
    output = getattr(response, "output", None)
    if not isinstance(model_id, str) or not model_id.strip() or not isinstance(output, list):
        raise InvalidProviderResponseError()
    model = ModelIdentifier(provider_id=_PROVIDER_ID, model_id=model_id)
    usage = _normalize_usage(getattr(response, "usage", None))
    texts: list[str] = []
    calls: list[ToolCall] = []
    call_ids: set[str] = set()
    for item in output:
        if getattr(item, "status", "completed") != "completed":
            raise InvalidProviderResponseError()
        item_type = getattr(item, "type", None)
        if item_type == "message":
            if getattr(item, "role", None) != "assistant":
                raise InvalidProviderResponseError()
            content = getattr(item, "content", None)
            if not isinstance(content, list):
                raise InvalidProviderResponseError()
            for part in content:
                if getattr(part, "type", None) != "output_text":
                    raise InvalidProviderResponseError()
                text = getattr(part, "text", None)
                if not isinstance(text, str):
                    raise InvalidProviderResponseError()
                texts.append(text)
        elif item_type == "function_call":
            call_id = getattr(item, "call_id", None)
            name = getattr(item, "name", None)
            arguments = getattr(item, "arguments", None)
            if (
                not isinstance(call_id, str)
                or not call_id.strip()
                or call_id in call_ids
                or not isinstance(name, str)
                or not name.strip()
                or name not in allowed_tool_names
                or not isinstance(arguments, str)
            ):
                raise InvalidProviderResponseError()
            try:
                parsed = json.loads(
                    arguments,
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_reject_json_constant,
                )
            except (json.JSONDecodeError, RecursionError, ValueError) as error:
                raise InvalidProviderResponseError() from error
            if not isinstance(parsed, dict):
                raise InvalidProviderResponseError()
            call_ids.add(call_id)
            calls.append(ToolCall(id=call_id, name=name, arguments=parsed))
        else:
            # Reasoning and other output items need provider continuation data not in ModelResponse.
            raise InvalidProviderResponseError()
    if calls and texts and any(text.strip() for text in texts):
        raise InvalidProviderResponseError()
    if calls:
        return ToolCallResponse(
            model=model,
            tool_calls=tuple(calls),
            finish_reason=FinishReason.TOOL_CALLS,
            usage=usage,
        )
    text = "".join(texts)
    if not text.strip():
        raise InvalidProviderResponseError()
    return TextResponse(model=model, text=text, finish_reason=FinishReason.STOP, usage=usage)


def _normalize_usage(usage: object) -> TokenUsage | None:
    if usage is None:
        return None
    input_tokens = getattr(usage, "input_tokens", None)
    output_tokens = getattr(usage, "output_tokens", None)
    try:
        return TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)
    except (TypeError, InvalidProviderResponseError) as error:
        raise InvalidProviderResponseError() from error


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in provider JSON object.")
        result[key] = value
    return result
