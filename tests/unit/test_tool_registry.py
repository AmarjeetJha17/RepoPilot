"""Deterministic tests for tool registration and argument validation."""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from pydantic import BaseModel, Field

from repopilot.agent.contracts import ToolCall
from repopilot.tools import (
    ToolDefinition,
    ToolRegistry,
    ToolRegistryError,
    ToolRegistryErrorCode,
    ValidatedToolCall,
)

pytestmark = pytest.mark.unit


class NestedOptions(BaseModel):
    count: int = Field(ge=1, le=5)


class SearchArguments(BaseModel):
    query: str = Field(min_length=2, max_length=8)
    limit: int = Field(ge=1, le=10)
    options: NestedOptions


def _definition() -> ToolDefinition:
    return ToolDefinition(
        name="search",
        description="Search the synthetic index.",
        arguments_model=SearchArguments,
    )


def _registry() -> ToolRegistry:
    return ToolRegistry((_definition(),))


def _call(
    arguments: Mapping[str, object] | object,
    *,
    call_id: str = "call-1",
    name: str = "search",
) -> ToolCall:
    return ToolCall(id=call_id, name=name, arguments=arguments)  # type: ignore[arg-type]


def test_registers_tools_in_deterministic_order() -> None:
    registry = ToolRegistry()
    first = _definition()
    second = ToolDefinition("lookup", "Look up a value.", SearchArguments, schema_version=2)

    registry.register(first)
    registry.register(second)

    assert registry.names == ("search", "lookup")
    assert registry.get("search") is first
    assert registry.get("lookup") is second


def test_rejects_duplicate_tool_registration_and_unknown_names() -> None:
    registry = _registry()

    with pytest.raises(ToolRegistryError) as duplicate:
        registry.register(_definition())
    assert duplicate.value.code is ToolRegistryErrorCode.DUPLICATE_TOOL

    with pytest.raises(ToolRegistryError) as unknown:
        registry.get("not_registered")
    assert unknown.value.code is ToolRegistryErrorCode.UNKNOWN_TOOL

    with pytest.raises(ToolRegistryError) as unknown_call:
        registry.validate_call(
            _call({"query": "ok", "limit": 1, "options": {"count": 1}}, name="missing")
        )
    assert unknown_call.value.code is ToolRegistryErrorCode.UNKNOWN_TOOL


def test_validates_arguments_without_coercion_and_returns_typed_result() -> None:
    result = _registry().validate_call(
        _call({"query": "repo", "limit": 3, "options": {"count": 2}})
    )

    assert isinstance(result, ValidatedToolCall)
    assert result.call_id == "call-1"
    assert result.name == "search"
    assert result.schema_version == 1
    assert isinstance(result.arguments, SearchArguments)
    assert result.arguments.query == "repo"
    assert result.arguments.options.count == 2


@pytest.mark.parametrize(
    "arguments",
    [
        {"query": "repo", "options": {"count": 2}},
        {"query": "repo", "limit": "3", "options": {"count": 2}},
        {"query": "repo", "limit": 3, "options": {"count": "2"}},
        {"query": "repo", "limit": 3, "options": {"count": 2}, "extra": True},
        {"query": "repo", "limit": 3, "options": {"count": 2, "nested_extra": 1}},
    ],
)
def test_rejects_missing_unknown_and_wrongly_typed_arguments(
    arguments: Mapping[str, object],
) -> None:
    with pytest.raises(ToolRegistryError) as caught:
        _registry().validate_call(_call(arguments))

    assert caught.value.code is ToolRegistryErrorCode.INVALID_ARGUMENTS
    assert "repo" not in str(caught.value)


@pytest.mark.parametrize(
    "arguments",
    [
        {"query": "x", "limit": 1, "options": {"count": 1}},
        {"query": "toolongggg", "limit": 1, "options": {"count": 1}},
        {"query": "valid", "limit": 0, "options": {"count": 1}},
        {"query": "valid", "limit": 11, "options": {"count": 1}},
        {"query": "valid", "limit": 1, "options": {"count": 0}},
        {"query": "valid", "limit": 1, "options": {"count": 6}},
    ],
)
def test_rejects_string_and_numeric_value_bounds(arguments: Mapping[str, object]) -> None:
    with pytest.raises(ToolRegistryError) as caught:
        _registry().validate_call(_call(arguments))

    assert caught.value.code is ToolRegistryErrorCode.INVALID_ARGUMENTS


def test_rejects_non_json_values_and_oversized_argument_payloads() -> None:
    registry = _registry()
    malformed = {"query": object(), "limit": 1, "options": {"count": 1}}
    with pytest.raises(ToolRegistryError) as invalid:
        registry.validate_call(_call(malformed))
    assert invalid.value.code is ToolRegistryErrorCode.INVALID_ARGUMENTS

    oversized = {"query": "x" * 17_000, "limit": 1, "options": {"count": 1}}
    with pytest.raises(ToolRegistryError) as large:
        registry.validate_call(_call(oversized))
    assert large.value.code is ToolRegistryErrorCode.ARGUMENTS_TOO_LARGE

    unicode_oversized = {"query": "é" * 9_000, "limit": 1, "options": {"count": 1}}
    with pytest.raises(ToolRegistryError) as unicode_large:
        registry.validate_call(_call(unicode_oversized))
    assert unicode_large.value.code is ToolRegistryErrorCode.ARGUMENTS_TOO_LARGE

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(ToolRegistryError) as recursive:
        registry.validate_call(_call(cyclic))
    assert recursive.value.code is ToolRegistryErrorCode.INVALID_ARGUMENTS


def test_validates_multiple_calls_in_order_and_rejects_duplicate_ids() -> None:
    registry = _registry()
    first = _call({"query": "one", "limit": 1, "options": {"count": 1}}, call_id="same")
    second = _call({"query": "two", "limit": 2, "options": {"count": 2}}, call_id="other")

    validated = registry.validate_calls((first, second))

    assert tuple(call.call_id for call in validated) == ("same", "other")
    with pytest.raises(ToolRegistryError) as duplicate:
        registry.validate_calls((first, first))
    assert duplicate.value.code is ToolRegistryErrorCode.DUPLICATE_CALL_ID


@pytest.mark.parametrize("call_id", ["", "   "])
def test_rejects_empty_call_identifiers(call_id: str) -> None:
    call = _call({"query": "ok", "limit": 1, "options": {"count": 1}}, call_id=call_id)

    with pytest.raises(ToolRegistryError) as caught:
        _registry().validate_call(call)

    assert caught.value.code is ToolRegistryErrorCode.INVALID_CALL_ID


def test_schema_export_preserves_nested_constraints_and_order() -> None:
    registry = ToolRegistry((_definition(), ToolDefinition("other", "Other.", SearchArguments)))

    schemas = registry.export_schemas()

    assert [schema["name"] for schema in schemas] == ["search", "other"]
    assert schemas[0]["description"] == "Search the synthetic index."
    assert schemas[0]["strict"] is False
    parameters = schemas[0]["parameters"]
    assert isinstance(parameters, dict)
    assert parameters["type"] == "object"
    assert parameters["additionalProperties"] is False
    assert parameters["properties"]["query"]["minLength"] == 2
    assert parameters["properties"]["query"]["maxLength"] == 8
    assert parameters["properties"]["limit"]["minimum"] == 1
    assert parameters["properties"]["limit"]["maximum"] == 10
    nested_name = parameters["$defs"]["NestedOptions"]
    assert nested_name["additionalProperties"] is False
    assert nested_name["properties"]["count"]["minimum"] == 1
    assert nested_name["properties"]["count"]["maximum"] == 5
    schemas[0]["name"] = "changed by caller"
    assert registry.export_schemas()[0]["name"] == "search"


def test_registry_instances_have_isolated_registration_state() -> None:
    first = ToolRegistry((_definition(),))
    second = ToolRegistry()

    assert first.names == ("search",)
    assert second.names == ()
    with pytest.raises(ToolRegistryError):
        second.get("search")
