"""Deterministic, network-free provider used by unit and contract tests."""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

from repopilot.providers.base import (
    ModelIdentifier,
    ModelProviderError,
    ModelRequest,
    ModelResponse,
    ModelRole,
    ProviderErrorCode,
    ProviderTimeoutError,
    TextResponse,
    ToolCallResponse,
)


class MockResponsesExhaustedError(ModelProviderError):
    """No scripted response remains for the next mock invocation."""

    code = ProviderErrorCode.MOCK_EXHAUSTED
    safe_message = "Mock provider response sequence is exhausted."


class MockProviderConcurrencyError(RuntimeError):
    """A second call overlapped a mock call that is waiting on its test gate."""


@dataclass(frozen=True, slots=True)
class MockRequestSummary:
    """Non-content request metadata; prompt and tool-schema values are not retained."""

    model: ModelIdentifier
    message_roles: tuple[ModelRole, ...]
    message_lengths: tuple[int, ...]
    tool_count: int


class MockModelProvider:
    """Return scripted outcomes in order and reject overlapping calls on one instance."""

    def __init__(
        self,
        outcomes: Sequence[ModelResponse | ModelProviderError],
        *,
        wait_before_response: asyncio.Event | None = None,
    ) -> None:
        self._outcomes = tuple(outcomes)
        if any(
            not isinstance(outcome, (ModelProviderError, TextResponse, ToolCallResponse))
            for outcome in self._outcomes
        ):
            raise TypeError("Mock outcomes must be model responses or provider errors.")
        self._wait_before_response = wait_before_response
        self._next_outcome = 0
        self._invocation_count = 0
        self._request_history: list[MockRequestSummary] = []
        self._active = False

    @property
    def invocation_count(self) -> int:
        """Number of calls attempted, including calls rejected for overlap."""
        return self._invocation_count

    @property
    def request_history(self) -> tuple[MockRequestSummary, ...]:
        """Safe request summaries without message contents or schema values."""
        return tuple(self._request_history)

    async def next_action(self, request: ModelRequest) -> ModelResponse:
        """Return the next outcome, honor request timeout, and propagate cancellation."""
        self._invocation_count += 1
        self._request_history.append(_summarize(request))
        if self._active:
            raise MockProviderConcurrencyError(
                "Mock provider does not permit overlapping requests on one instance."
            )

        self._active = True
        try:
            async with asyncio.timeout(request.timeout_seconds):
                if self._wait_before_response is not None:
                    await self._wait_before_response.wait()
            if self._next_outcome >= len(self._outcomes):
                raise MockResponsesExhaustedError()
            outcome = self._outcomes[self._next_outcome]
            self._next_outcome += 1
            if isinstance(outcome, ModelProviderError):
                raise outcome
            return outcome
        except TimeoutError as error:
            raise ProviderTimeoutError() from error
        finally:
            self._active = False


def _summarize(request: ModelRequest) -> MockRequestSummary:
    if not isinstance(request, ModelRequest):
        raise TypeError("Mock provider request must be a ModelRequest value.")
    return MockRequestSummary(
        model=request.model,
        message_roles=tuple(message.role for message in request.messages),
        message_lengths=tuple(len(message.content) for message in request.messages),
        tool_count=len(request.tools),
    )
