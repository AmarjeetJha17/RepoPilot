"""Smoke tests for the current package and architectural contracts."""

from dataclasses import FrozenInstanceError
from importlib import import_module
from importlib.metadata import version

import pytest

from repopilot.agent.contracts import ToolCall, ToolResult
from repopilot.agent.state import RunStatus
from repopilot.security.policy import PolicyDecision

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "module_name",
    [
        "repopilot",
        "repopilot.agent",
        "repopilot.application",
        "repopilot.cli",
        "repopilot.context",
        "repopilot.evaluation",
        "repopilot.observability",
        "repopilot.persistence",
        "repopilot.providers",
        "repopilot.sandbox",
        "repopilot.security",
        "repopilot.tools",
        "repopilot.ui",
    ],
)
def test_package_imports(module_name: str) -> None:
    assert import_module(module_name).__name__ == module_name


def test_distribution_version_is_available() -> None:
    assert version("repopilot") == "0.1.0"


def test_tool_call_retains_its_typed_fields() -> None:
    arguments = {"path": "src/repopilot/__init__.py"}
    call = ToolCall(id="call-1", name="read_file", arguments=arguments)

    assert (call.id, call.name, call.arguments) == ("call-1", "read_file", arguments)


def test_tool_call_is_frozen() -> None:
    call = ToolCall(id="call-1", name="read_file", arguments={})

    with pytest.raises(FrozenInstanceError):
        call.id = "call-2"  # type: ignore[misc]


def test_tool_result_defaults_to_not_truncated() -> None:
    result = ToolResult(call_id="call-1", ok=True, output="done")

    assert result.truncated is False


def test_tool_result_can_report_truncated_output() -> None:
    result = ToolResult(call_id="call-1", ok=True, output="partial", truncated=True)

    assert result.truncated is True


def test_run_status_values_match_the_documented_lifecycle() -> None:
    assert [status.value for status in RunStatus] == [
        "CREATED",
        "INSPECTING",
        "PLANNING",
        "EXECUTING",
        "VERIFYING",
        "AWAITING_APPROVAL",
        "COMPLETED",
        "PARTIAL",
        "BLOCKED",
        "FAILED",
        "CANCELLED",
    ]


def test_policy_decision_values_are_stable() -> None:
    assert [decision.value for decision in PolicyDecision] == ["allow", "deny", "approval"]
