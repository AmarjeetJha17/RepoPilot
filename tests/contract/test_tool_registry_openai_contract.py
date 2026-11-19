"""Contract between provider-neutral tool schemas and the OpenAI adapter."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import cast

import pytest
from openai import AsyncOpenAI
from openai.types.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from repopilot.providers.adapters.openai import OpenAIModelProvider
from repopilot.providers.base import ModelIdentifier, ModelMessage, ModelRequest, ModelRole
from repopilot.tools import ToolDefinition, ToolRegistry

pytestmark = pytest.mark.contract


class InspectArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=100)
    depth: int = Field(ge=0, le=4)


class _Responses:
    def __init__(self) -> None:
        self.request: dict[str, object] | None = None

    async def create(self, **kwargs: object) -> Response:
        self.request = kwargs
        text = SimpleNamespace(type="output_text", text="ready")
        message = SimpleNamespace(type="message", role="assistant", content=[text])
        return Response.model_construct(
            status="completed",
            incomplete_details=None,
            model="gpt-test",
            output=[message],
            usage=None,
        )


class _Client:
    def __init__(self) -> None:
        self.responses = _Responses()

    def with_options(self, **kwargs: object) -> _Client:
        assert kwargs == {"max_retries": 0}
        return self


def test_registry_schema_is_forwarded_by_existing_openai_adapter() -> None:
    registry = ToolRegistry(
        (ToolDefinition("inspect", "Read a bounded file excerpt.", InspectArguments),)
    )
    schema = registry.export_schemas()[0]
    client = _Client()
    provider = OpenAIModelProvider(client=cast(AsyncOpenAI, client))
    request = ModelRequest(
        model=ModelIdentifier("openai", "gpt-test"),
        messages=(ModelMessage(ModelRole.USER, "inspect"),),
        tools=(schema,),
    )

    asyncio.run(provider.next_action(request))

    assert client.responses.request is not None
    assert client.responses.request["tools"] == [{"type": "function", **schema}]
