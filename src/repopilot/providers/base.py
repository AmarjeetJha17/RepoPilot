"""Provider-neutral request, response, and error contracts."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from typing import ClassVar, Literal, Protocol

from repopilot.agent.contracts import ToolCall


class ModelRole(StrEnum):
    """Conversation roles shared by provider adapters."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class FinishReason(StrEnum):
    """Stable, provider-independent reasons for a response ending."""

    STOP = "stop"
    TOOL_CALLS = "tool_calls"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    OTHER = "other"


class ProviderErrorCode(StrEnum):
    """Stable categories used by future application retry and reporting logic."""

    AUTHENTICATION = "authentication_failed"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"
    UNAVAILABLE = "unavailable"
    PERMANENT = "permanent_failure"
    MOCK_EXHAUSTED = "mock_responses_exhausted"


class ModelProviderError(Exception):
    """Base provider failure with a safe message and stable retry classification."""

    code: ClassVar[ProviderErrorCode] = ProviderErrorCode.PERMANENT
    retryable: ClassVar[bool] = False
    safe_message: ClassVar[str] = "Model provider request failed."

    def __init__(self) -> None:
        super().__init__(self.safe_message)


class ProviderAuthenticationError(ModelProviderError):
    """Provider rejected configured credentials; retrying unchanged is not useful."""

    code = ProviderErrorCode.AUTHENTICATION
    safe_message = "Model provider authentication failed."


class ProviderRateLimitError(ModelProviderError):
    """Provider rate limit may clear after its retry window."""

    code = ProviderErrorCode.RATE_LIMITED
    retryable = True
    safe_message = "Model provider rate limit reached."


class ProviderTimeoutError(ModelProviderError):
    """Provider did not produce a response before the request deadline."""

    code = ProviderErrorCode.TIMEOUT
    retryable = True
    safe_message = "Model provider request timed out."


class InvalidProviderResponseError(ModelProviderError):
    """Provider output did not satisfy the normalized response contract."""

    code = ProviderErrorCode.INVALID_RESPONSE
    safe_message = "Model provider returned an invalid response."


class ProviderUnavailableError(ModelProviderError):
    """Provider is temporarily unavailable and may recover."""

    code = ProviderErrorCode.UNAVAILABLE
    retryable = True
    safe_message = "Model provider is temporarily unavailable."


class ProviderPermanentError(ModelProviderError):
    """Provider reported a permanent request failure."""

    code = ProviderErrorCode.PERMANENT
    safe_message = "Model provider reported a permanent failure."


@dataclass(frozen=True, slots=True)
class ModelIdentifier:
    """Provider and model names without SDK-specific configuration fields."""

    provider_id: str
    model_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.provider_id, str)
            or not isinstance(self.model_id, str)
            or not self.provider_id.strip()
            or not self.model_id.strip()
        ):
            raise ValueError("Provider and model identifiers must be non-empty.")


@dataclass(frozen=True, slots=True)
class ModelMessage:
    """One role-tagged conversation message; its content remains untrusted text."""

    role: ModelRole
    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, ModelRole):
            raise TypeError("Message role must be a ModelRole value.")
        if not isinstance(self.content, str):
            raise TypeError("Message content must be text.")
        if not isinstance(self.tool_calls, tuple) or any(
            not isinstance(call, ToolCall) for call in self.tool_calls
        ):
            raise TypeError("Message tool calls must be a tuple of ToolCall values.")
        if self.tool_call_id is not None and not isinstance(self.tool_call_id, str):
            raise TypeError("Message tool_call_id must be text when provided.")


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """Immutable model selection, conversation, optional tool schemas, and deadline."""

    model: ModelIdentifier
    messages: tuple[ModelMessage, ...]
    tools: tuple[Mapping[str, object], ...] = ()
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not isinstance(self.model, ModelIdentifier):
            raise TypeError("Request model must be a ModelIdentifier value.")
        if not isinstance(self.messages, tuple) or any(
            not isinstance(message, ModelMessage) for message in self.messages
        ):
            raise TypeError("Request messages must be a tuple of ModelMessage values.")
        if not isinstance(self.tools, tuple) or any(
            not isinstance(tool, Mapping) for tool in self.tools
        ):
            raise TypeError("Request tools must be a tuple of schema mappings.")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int | float)
            or not isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("Request timeout must be positive and finite.")


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token counts reported by a provider; individual counts may be unavailable."""

    input_tokens: int | None = None
    output_tokens: int | None = None

    def __post_init__(self) -> None:
        counts = (self.input_tokens, self.output_tokens)
        if all(count is None for count in counts) or any(
            count is not None
            and (not isinstance(count, int) or isinstance(count, bool) or count < 0)
            for count in counts
        ):
            raise InvalidProviderResponseError()


@dataclass(frozen=True, slots=True)
class TextResponse:
    """Non-empty model text output with normalized finish and optional usage metadata."""

    model: ModelIdentifier
    text: str
    finish_reason: FinishReason
    usage: TokenUsage | None = None
    kind: Literal["text"] = field(default="text", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.model, ModelIdentifier) or not isinstance(
            self.finish_reason, FinishReason
        ):
            raise InvalidProviderResponseError()
        if not isinstance(self.text, str) or not self.text.strip():
            raise InvalidProviderResponseError()
        if self.finish_reason is FinishReason.TOOL_CALLS:
            raise InvalidProviderResponseError()
        if self.usage is not None and not isinstance(self.usage, TokenUsage):
            raise InvalidProviderResponseError()


@dataclass(frozen=True, slots=True)
class ToolCallResponse:
    """One or more untrusted proposed tool calls; authorization remains separate."""

    model: ModelIdentifier
    tool_calls: tuple[ToolCall, ...]
    finish_reason: FinishReason
    usage: TokenUsage | None = None
    kind: Literal["tool_calls"] = field(default="tool_calls", init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model, ModelIdentifier)
            or self.finish_reason is not FinishReason.TOOL_CALLS
        ):
            raise InvalidProviderResponseError()
        if (
            not isinstance(self.tool_calls, tuple)
            or not self.tool_calls
            or any(not isinstance(call, ToolCall) for call in self.tool_calls)
        ):
            raise InvalidProviderResponseError()
        if self.usage is not None and not isinstance(self.usage, TokenUsage):
            raise InvalidProviderResponseError()


type ModelResponse = TextResponse | ToolCallResponse


class ModelProvider(Protocol):
    """Normalize provider I/O while leaving authorization to trusted application code."""

    supports_conversation_continuation: bool
    """Whether the adapter can faithfully represent prior calls and tool results."""

    allows_repository_feedback: bool
    """Whether this provider is configured to receive repository data in follow-up requests."""

    async def next_action(self, request: ModelRequest) -> ModelResponse:
        """Honor the request timeout and propagate cancellation through task cancellation."""
        ...
