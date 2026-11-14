"""Deterministic tests for read-only environment checks."""

import subprocess

import pytest

from repopilot.application.services import CheckStatus, inspect_environment

pytestmark = pytest.mark.unit


def _successful_command(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, 0)


def test_environment_checks_pass_for_supported_python_and_local_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr("repopilot.application.services.sys.version_info", (3, 12, 0))

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return _successful_command(args)

    monkeypatch.setattr("repopilot.application.services.subprocess.run", fake_run)

    report = inspect_environment()

    assert all(check.status is CheckStatus.PASS for check in report.checks)
    assert report.exit_code == 0
    assert [args for args, _ in calls] == [
        ["git", "--version"],
        ["uv", "--version"],
        ["docker", "--version"],
        ["git", "rev-parse", "--show-toplevel"],
    ]
    assert all(kwargs["shell"] is False for _, kwargs in calls)
    assert all(kwargs["timeout"] == 5 for _, kwargs in calls)


def test_missing_optional_tools_are_warnings_not_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if args[0] in {"uv", "docker"}:
            raise FileNotFoundError(args[0])
        if args == ["git", "rev-parse", "--show-toplevel"]:
            return subprocess.CompletedProcess(args, 128)
        return _successful_command(args)

    monkeypatch.setattr("repopilot.application.services.subprocess.run", fake_run)

    report = inspect_environment()
    statuses = {check.name: check.status for check in report.checks}

    assert statuses["uv executable"] is CheckStatus.WARN
    assert statuses["Docker CLI"] is CheckStatus.WARN
    assert statuses["Git repository"] is CheckStatus.WARN
    assert report.exit_code == 0


def test_subprocess_timeouts_are_reported_without_failing_doctor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args, timeout=kwargs["timeout"])

    monkeypatch.setattr("repopilot.application.services.subprocess.run", fake_run)

    report = inspect_environment()

    assert all(
        check.status is CheckStatus.WARN for check in report.checks if check.name != "Python"
    )
    assert report.exit_code == 0


def test_execution_errors_are_reported_without_exception_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "api_key=do-not-print"

    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise OSError(secret)

    monkeypatch.setattr("repopilot.application.services.subprocess.run", fake_run)

    report = inspect_environment()

    assert all("api_key" not in check.detail for check in report.checks)
    assert report.exit_code == 0


def test_incompatible_python_version_causes_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("repopilot.application.services.sys.version_info", (3, 11, 9))
    monkeypatch.setattr("repopilot.application.services.subprocess.run", _successful_command)

    report = inspect_environment()

    assert report.checks[0].status is CheckStatus.FAIL
    assert report.exit_code == 1


def test_command_output_is_not_included_in_check_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "token=never-render-this"

    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout=secret, stderr=secret)

    monkeypatch.setattr("repopilot.application.services.subprocess.run", fake_run)

    report = inspect_environment()

    assert all(secret not in check.detail for check in report.checks)
