"""Portable contracts for fixed sandbox command requests."""

from __future__ import annotations

import pytest

from repopilot.sandbox.execution import (
    SandboxConfig,
    SandboxLimits,
    SandboxRequest,
    VerificationCommand,
    _command_argv,
)


def test_image_requires_immutable_sha256_digest() -> None:
    SandboxConfig("registry.example:5000/repopilot@sha256:" + "a" * 64)

    with pytest.raises(ValueError):
        SandboxConfig("registry.example/repopilot:latest")


def test_request_rejects_non_normalized_and_duplicate_paths() -> None:
    with pytest.raises(ValueError):
        SandboxRequest(VerificationCommand.PYTEST, ("../outside.py",))
    with pytest.raises(ValueError):
        SandboxRequest(VerificationCommand.PYTEST, ("module.py", "module.py"))


def test_python_syntax_argv_is_fixed_and_targets_are_positional() -> None:
    argv = _command_argv(SandboxRequest(VerificationCommand.PYTHON_SYNTAX, ("src/module.py",)))

    assert argv[:4] == ("python", "-I", "-B", "-c")
    assert argv[-1] == "/workspace/src/module.py"
    assert "shell" not in argv


def test_pytest_argv_disables_project_config_and_plugin_autoload() -> None:
    argv = _command_argv(SandboxRequest(VerificationCommand.PYTEST, ("tests/test_app.py",)))

    assert argv[:5] == ("python", "-I", "-B", "-m", "pytest")
    assert "-c" in argv and "/dev/null" in argv
    assert "no:cacheprovider" in argv
    assert argv[-1] == "/workspace/tests/test_app.py"


def test_resource_limits_reject_unbounded_values() -> None:
    with pytest.raises(ValueError):
        SandboxLimits(timeout_seconds=601)
