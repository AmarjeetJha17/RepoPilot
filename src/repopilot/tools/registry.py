"""Explicit tool registry and untrusted argument-validation boundary."""

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from repopilot.agent.contracts import ToolCall
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.errors import ToolRegistryError, ToolRegistryErrorCode

MAX_TOOL_ARGUMENT_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class ValidatedToolCall:
    """A proposal whose name and arguments passed its registered schema only."""

    call_id: str
    name: str
    arguments: BaseModel
    schema_version: int


class ToolRegistry:
    """Keep an instance-local ordered allowlist and validate calls without executing them."""

    def __init__(self, definitions: Iterable[ToolDefinition] = ()) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        for definition in definitions:
            self.register(definition)

    @property
    def names(self) -> tuple[str, ...]:
        """Registered names in deterministic insertion order."""
        return tuple(self._definitions)

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        """Definitions in deterministic insertion order."""
        return tuple(self._definitions.values())

    def register(self, definition: ToolDefinition) -> None:
        """Add one explicit definition, rejecting duplicate names."""
        if not isinstance(definition, ToolDefinition):
            raise TypeError("Only ToolDefinition instances can be registered.")
        if definition.name in self._definitions:
            raise ToolRegistryError(ToolRegistryErrorCode.DUPLICATE_TOOL)
        self._definitions[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        """Return a registered definition or reject an unlisted name."""
        try:
            return self._definitions[name]
        except (KeyError, TypeError) as error:
            raise ToolRegistryError(ToolRegistryErrorCode.UNKNOWN_TOOL) from error

    def export_schemas(self) -> list[dict[str, object]]:
        """Export fresh JSON Schema function definitions in registration order."""
        return [definition.provider_schema() for definition in self._definitions.values()]

    def validate_call(self, call: ToolCall) -> ValidatedToolCall:
        """Validate one untrusted proposal without authorizing or invoking a handler."""
        if not isinstance(call, ToolCall):
            raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS)
        _validate_call_id(call.id)
        definition = self.get(call.name)
        payload = _serialize_arguments(call.arguments)
        if len(payload.encode("utf-8")) > MAX_TOOL_ARGUMENT_BYTES:
            raise ToolRegistryError(ToolRegistryErrorCode.ARGUMENTS_TOO_LARGE)
        try:
            arguments = definition.arguments_model.model_validate_json(
                payload,
                strict=True,
                extra="forbid",
            )
        except ValidationError as error:
            raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS) from error
        return ValidatedToolCall(
            call_id=call.id,
            name=call.name,
            arguments=arguments,
            schema_version=definition.schema_version,
        )

    def validate_calls(self, calls: Sequence[ToolCall]) -> tuple[ValidatedToolCall, ...]:
        """Validate a batch in order and reject duplicate identifiers atomically."""
        if not isinstance(calls, Sequence) or isinstance(calls, str | bytes):
            raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS)
        seen_ids: set[str] = set()
        validated: list[ValidatedToolCall] = []
        for call in calls:
            if not isinstance(call, ToolCall):
                raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS)
            _validate_call_id(call.id)
            if call.id in seen_ids:
                raise ToolRegistryError(ToolRegistryErrorCode.DUPLICATE_CALL_ID)
            seen_ids.add(call.id)
            validated.append(self.validate_call(call))
        return tuple(validated)


def _validate_call_id(call_id: object) -> None:
    if not isinstance(call_id, str) or not call_id.strip():
        raise ToolRegistryError(ToolRegistryErrorCode.INVALID_CALL_ID)


def _serialize_arguments(arguments: object) -> str:
    if not isinstance(arguments, Mapping):
        raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS)
    try:
        if _estimated_json_size(arguments) > MAX_TOOL_ARGUMENT_BYTES:
            raise ToolRegistryError(ToolRegistryErrorCode.ARGUMENTS_TOO_LARGE)
        return json.dumps(
            dict(arguments), ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
    except ToolRegistryError:
        raise
    except (RecursionError, TypeError, ValueError) as error:
        raise ToolRegistryError(ToolRegistryErrorCode.INVALID_ARGUMENTS) from error


def _estimated_json_size(value: object) -> int:
    if value is None:
        return 4
    if type(value) is bool:
        return 4 if value else 5
    if type(value) is str:
        return len(value) + 2
    if type(value) is int:
        if value.bit_length() > MAX_TOOL_ARGUMENT_BYTES * 4:
            return MAX_TOOL_ARGUMENT_BYTES + 1
        return len(str(value))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Arguments contain a non-finite number.")
        return len(repr(value))
    if isinstance(value, Mapping):
        if len(value) > MAX_TOOL_ARGUMENT_BYTES:
            return MAX_TOOL_ARGUMENT_BYTES + 1
        size = 2
        for index, (key, item) in enumerate(value.items()):
            if type(key) is not str:
                raise TypeError("Argument object keys must be strings.")
            size += len(key) + 2 + 1 + (index > 0)
            size += _estimated_json_size(item)
            if size > MAX_TOOL_ARGUMENT_BYTES:
                return MAX_TOOL_ARGUMENT_BYTES + 1
        return size
    if isinstance(value, list):
        if len(value) > MAX_TOOL_ARGUMENT_BYTES:
            return MAX_TOOL_ARGUMENT_BYTES + 1
        size = 2
        for index, item in enumerate(value):
            size += int(index > 0) + _estimated_json_size(item)
            if size > MAX_TOOL_ARGUMENT_BYTES:
                return MAX_TOOL_ARGUMENT_BYTES + 1
        return size
    raise TypeError("Arguments contain a non-JSON value.")
