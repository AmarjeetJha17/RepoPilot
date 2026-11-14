"""CLI and presentation integration tests."""

import re
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repopilot.application import services
from repopilot.application.services import CheckStatus, DoctorReport, EnvironmentCheck
from repopilot.cli.main import app

pytestmark = pytest.mark.integration

runner = CliRunner()
_ANSI_ESCAPE_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _normalize_help_text(output: str) -> str:
    without_ansi = _ANSI_ESCAPE_SEQUENCE.sub("", output)
    return " ".join(without_ansi.split())


def test_help_lists_doctor_and_version_option() -> None:
    result = runner.invoke(app, ["--help"], color=False, terminal_width=100)
    help_text = _normalize_help_text(result.stdout)

    assert result.exit_code == 0
    assert "doctor" in help_text
    assert "--version" in help_text


def test_help_text_normalization_strips_ansi_codes() -> None:
    styled_help = "\x1b[1m--ver\x1b[0msion"

    assert "--version" in _normalize_help_text(styled_help)


def test_version_option_uses_installed_distribution_metadata() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"RepoPilot {version('repopilot')}"


def test_doctor_displays_check_statuses_and_returns_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = DoctorReport(
        checks=(
            EnvironmentCheck("Python", CheckStatus.PASS, "Python 3.12 is supported."),
            EnvironmentCheck("uv executable", CheckStatus.WARN, "uv was not found."),
        )
    )
    monkeypatch.setattr("repopilot.cli.main.inspect_environment", lambda: report)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "[PASS]" in result.stdout
    assert "[WARN]" in result.stdout


def test_doctor_returns_nonzero_when_a_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = DoctorReport(
        checks=(EnvironmentCheck("Python", CheckStatus.FAIL, "Python is unsupported."),)
    )
    monkeypatch.setattr("repopilot.cli.main.inspect_environment", lambda: report)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert "[FAIL]" in result.stdout


def test_doctor_does_not_render_executable_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "token=do-not-print"

    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout=secret, stderr=secret)

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert secret not in result.stdout


def test_module_entry_point_invokes_the_same_cli() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "repopilot", "--help"],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0
    assert "doctor" in result.stdout
