"""Contracts for the explicitly registered read-only repository tools."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from repopilot.security.capabilities import Capability
from repopilot.tools.readonly import (
    DiscoverFilesArguments,
    IndexPythonArguments,
    ReadTextArguments,
    SearchLiteralArguments,
    create_readonly_tool_registry,
)

pytestmark = pytest.mark.unit


def test_factory_registers_only_four_explicit_scoped_tools() -> None:
    first = create_readonly_tool_registry()
    second = create_readonly_tool_registry()

    assert first.names == (
        "repo_discover_files",
        "repo_read_text",
        "repo_search_literal",
        "repo_index_python",
    )
    assert first is not second
    definitions = {item.name: item for item in first.definitions}
    assert definitions["repo_discover_files"].capabilities == frozenset(
        {Capability.REPOSITORY_READ}
    )
    assert definitions["repo_discover_files"].resource_type == "directory"
    assert definitions["repo_discover_files"].resource_fields == ("directory",)
    assert definitions["repo_read_text"].resource_type == "file"
    assert definitions["repo_read_text"].resource_fields == ("path",)
    assert definitions["repo_search_literal"].capabilities == frozenset(
        {Capability.REPOSITORY_SEARCH}
    )
    assert definitions["repo_search_literal"].resource_fields == ("paths",)
    assert definitions["repo_index_python"].resource_fields == ("paths",)


def test_arguments_are_strict_and_reject_unbounded_or_extra_values() -> None:
    with pytest.raises(ValidationError):
        ReadTextArguments.model_validate({"path": "src/main.py", "max_bytes": "500"}, strict=True)
    with pytest.raises(ValidationError):
        ReadTextArguments.model_validate({"path": "src/main.py", "max_bytes": 10_000}, strict=True)
    with pytest.raises(ValidationError):
        DiscoverFilesArguments.model_validate({"directory": "../"}, strict=True)
    with pytest.raises(ValidationError):
        SearchLiteralArguments.model_validate({"paths": [], "query": "x"}, strict=True)
    with pytest.raises(ValidationError):
        IndexPythonArguments.model_validate(
            {"paths": ["src/a.py"], "unexpected": True}, strict=True
        )


def test_all_tool_schemas_have_directory_or_resource_scope_fields() -> None:
    registry = create_readonly_tool_registry()

    schemas = registry.export_schemas()

    assert [schema["name"] for schema in schemas] == list(registry.names)
    assert all("parameters" in schema for schema in schemas)
    assert all(definition.resource_fields for definition in registry.definitions)
