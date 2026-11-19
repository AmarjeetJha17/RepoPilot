"""Structural contract test for ModelProvider implementations."""

import asyncio

import pytest

from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    TextResponse,
)
from repopilot.providers.mock import MockModelProvider

pytestmark = pytest.mark.contract


def _request() -> ModelRequest:
    return ModelRequest(
        model=ModelIdentifier(provider_id="mock", model_id="contract-test"),
        messages=(),
    )


async def _request_output(provider: ModelProvider, request: ModelRequest) -> ModelResponse:
    return await provider.next_action(request)


def test_mock_provider_satisfies_provider_contract() -> None:
    response = TextResponse(
        model=_request().model,
        text="contract response",
        finish_reason=FinishReason.STOP,
    )
    provider = MockModelProvider((response,))

    result = asyncio.run(_request_output(provider, _request()))

    assert isinstance(result, TextResponse)
    assert result.text == "contract response"
