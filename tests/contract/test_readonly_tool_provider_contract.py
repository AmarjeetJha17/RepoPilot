"""Provider-neutral request compatibility for read-only repository tool schemas."""

from __future__ import annotations

import pytest

from repopilot.providers.base import ModelIdentifier, ModelMessage, ModelRequest, ModelRole
from repopilot.tools import create_readonly_tool_registry

pytestmark = pytest.mark.contract


def test_readonly_schemas_fit_provider_neutral_model_request() -> None:
    registry = create_readonly_tool_registry()

    request = ModelRequest(
        model=ModelIdentifier("mock", "readonly-contract"),
        messages=(ModelMessage(ModelRole.USER, "Inspect these files."),),
        tools=tuple(registry.export_schemas()),
    )

    assert tuple(tool["name"] for tool in request.tools) == registry.names
    assert all(tool["parameters"]["type"] == "object" for tool in request.tools)
