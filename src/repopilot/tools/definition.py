"""Provider-neutral, typed tool argument definitions and JSON Schema export."""

from dataclasses import dataclass
from typing import Literal, cast

from pydantic import BaseModel

from repopilot.security.capabilities import Capability


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Named tool contract; it describes arguments and does not carry an executor."""

    name: str
    description: str
    arguments_model: type[BaseModel]
    schema_version: int = 1
    capabilities: frozenset[Capability] = frozenset()
    resource_fields: tuple[str, ...] = ()
    resource_type: Literal["file", "directory"] = "file"

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Tool name must be non-empty.")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("Tool description must be non-empty.")
        if not isinstance(self.arguments_model, type) or not issubclass(
            self.arguments_model, BaseModel
        ):
            raise TypeError("Tool arguments must use a Pydantic BaseModel type.")
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version < 1
        ):
            raise ValueError("Tool schema version must be a positive integer.")
        if not isinstance(self.capabilities, frozenset) or any(
            not isinstance(capability, Capability) for capability in self.capabilities
        ):
            raise TypeError("Tool capabilities must be a frozenset of known Capability values.")
        if (
            not isinstance(self.resource_fields, tuple)
            or any(
                not isinstance(field, str)
                or not field
                or field not in self.arguments_model.model_fields
                for field in self.resource_fields
            )
            or len(set(self.resource_fields)) != len(self.resource_fields)
        ):
            raise ValueError("Tool resource fields must be unique argument model fields.")
        if self.resource_type not in {"file", "directory"}:
            raise ValueError("Tool resource type must be 'file' or 'directory'.")
        self.provider_schema()

    def provider_schema(self) -> dict[str, object]:
        """Return the OpenAI-adapter-compatible function schema without SDK imports."""
        parameters = self.arguments_model.model_json_schema(mode="validation")
        if parameters.get("type") != "object":
            raise ValueError("Tool arguments schema must have an object at its root.")
        _close_object_schemas(parameters)
        return {
            "name": self.name,
            "description": self.description,
            "parameters": cast(dict[str, object], parameters),
            # Local validation remains authoritative; provider schemas may contain richer bounds.
            "strict": False,
        }


def _close_object_schemas(schema: object) -> None:
    if isinstance(schema, dict):
        if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
            schema["additionalProperties"] = False
        for value in schema.values():
            _close_object_schemas(value)
    elif isinstance(schema, list):
        for value in schema:
            _close_object_schemas(value)
