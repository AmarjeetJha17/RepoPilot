"""Security checks for untrusted provider-proposed tool arguments."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field, field_validator

from repopilot.agent.contracts import ToolCall
from repopilot.tools import ToolDefinition, ToolRegistry, ToolRegistryError, ToolRegistryErrorCode

pytestmark = pytest.mark.security


def test_oversized_payload_is_rejected_before_model_validation() -> None:
    validator_calls: list[str] = []

    class Arguments(BaseModel):
        content: str = Field(max_length=20_000)

        @field_validator("content")
        @classmethod
        def record_validation(cls, value: str) -> str:
            validator_calls.append(value)
            return value

    registry = ToolRegistry((ToolDefinition("inspect", "Inspect text.", Arguments),))
    call = ToolCall(id="call-1", name="inspect", arguments={"content": "x" * 17_000})

    with pytest.raises(ToolRegistryError) as caught:
        registry.validate_call(call)

    assert caught.value.code is ToolRegistryErrorCode.ARGUMENTS_TOO_LARGE
    assert validator_calls == []


def test_nested_non_string_mapping_keys_are_rejected_without_coercion() -> None:
    class Arguments(BaseModel):
        values: dict[str, int]

    registry = ToolRegistry((ToolDefinition("inspect", "Inspect values.", Arguments),))
    call = ToolCall(id="call-1", name="inspect", arguments={"values": {1: 2}})

    with pytest.raises(ToolRegistryError) as caught:
        registry.validate_call(call)

    assert caught.value.code is ToolRegistryErrorCode.INVALID_ARGUMENTS


def test_validation_has_no_authorization_or_execution_surface() -> None:
    class Arguments(BaseModel):
        value: int

    definition = ToolDefinition("inspect", "Inspect a value.", Arguments)
    registry = ToolRegistry((definition,))
    result = registry.validate_call(ToolCall(id="call-1", name="inspect", arguments={"value": 1}))

    assert result.arguments.value == 1
    assert not hasattr(registry, "authorize")
    assert not hasattr(registry, "execute")
    assert not hasattr(registry, "dispatch")
    assert not hasattr(definition, "handler")
