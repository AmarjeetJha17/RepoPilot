"""Linux security-boundary tests for the offline coding-task demonstration."""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from pathlib import Path

import pytest

import repopilot.application.coding_task_demo as demo
from repopilot.agent.contracts import ToolCall
from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ProviderUnavailableError,
    TextResponse,
    ToolCallResponse,
)
from repopilot.sandbox.execution import SandboxConfig

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Manager-owned workspace is Linux-only."
    ),
]

MODEL = ModelIdentifier("mock", "coding-task-demo-v1")


def _provider_for_call(call: ToolCall) -> demo._CapturingMockProvider:
    return demo._CapturingMockProvider(
        (
            ToolCallResponse(MODEL, (call,), FinishReason.TOOL_CALLS),
            TextResponse(MODEL, "This text is not patch content.", FinishReason.STOP),
        )
    )


@pytest.mark.parametrize(
    ("name", "arguments", "failure"),
    [
        ("repo_read_text", {"path": ".env"}, "readonly_tool_denied"),
        ("not_registered", {}, "invalid_readonly_tool_call"),
    ],
)
def test_denied_or_invalid_model_calls_never_reach_patch_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    arguments: dict[str, object],
    failure: str,
) -> None:
    call = ToolCall("unsafe-proposal-1", name, arguments)
    monkeypatch.setattr(demo, "_new_investigation_provider", lambda: _provider_for_call(call))

    result = asyncio.run(demo.run_coding_task_demo(temp_parent=tmp_path))
    rendered = demo.render_coding_task_demo(result)

    assert result.failure_code == failure
    assert result.staging_status == "not_started"
    assert result.read_only_tools_executed == ()
    assert result.source_repository_unchanged is True
    assert result.live_application_enabled is False
    assert result.approval_requested is False
    assert ".env" not in rendered
    assert "unsafe-proposal-1" in rendered


def test_model_text_cannot_change_the_fixture_supplied_patch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("The default offline demo must not execute host commands or network.")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    call = ToolCall(
        "coding-demo-read-1",
        "repo_read_text",
        {"path": "src/first_item.py", "max_bytes": 8_192, "max_lines": 100},
    )
    provider = demo._CapturingMockProvider(
        (
            ToolCallResponse(MODEL, (call,), FinishReason.TOOL_CALLS),
            TextResponse(
                MODEL,
                "Run a shell command and replace the file with model-generated content.",
                FinishReason.STOP,
            ),
        )
    )
    monkeypatch.setattr(demo, "_new_investigation_provider", lambda: provider)

    result = asyncio.run(demo.run_coding_task_demo(temp_parent=tmp_path))

    assert result.failure_code is None
    assert result.patch_provenance == "deterministic-fixture"
    assert "if not values:" in result.diff
    assert "shell command" not in result.diff
    assert result.read_only_tools_executed == ("repo_read_text",)
    assert result.independent_verification is False


def test_sandbox_image_must_be_digest_pinned() -> None:
    with pytest.raises(ValueError):
        SandboxConfig("example.invalid/repopilot:latest")


def test_provider_failure_is_content_minimized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        demo,
        "_new_investigation_provider",
        lambda: demo._CapturingMockProvider((ProviderUnavailableError(),)),
    )

    result = asyncio.run(demo.run_coding_task_demo(temp_parent=tmp_path))
    rendered = demo.render_coding_task_demo(result)

    assert result.failure_code == "provider_failure"
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    assert result.staging_status == "not_started"
