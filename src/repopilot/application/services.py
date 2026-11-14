"""Application-level coordination for read-only environment checks."""

import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

CHECK_TIMEOUT_SECONDS = 5


class CheckStatus(StrEnum):
    """A human-readable outcome for one doctor check."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class EnvironmentCheck:
    """One environment check and its safe-to-display summary."""

    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Read-only checks; a nonzero exit is reserved for failed requirements."""

    checks: tuple[EnvironmentCheck, ...]

    @property
    def exit_code(self) -> int:
        """Return 1 if any required check failed, otherwise 0, including warnings."""
        return int(any(check.status is CheckStatus.FAIL for check in self.checks))


def _python_check() -> EnvironmentCheck:
    version = sys.version_info
    version_text = f"Python {version[0]}.{version[1]}.{version[2]}"
    if version < (3, 12):
        return EnvironmentCheck(
            "Python",
            CheckStatus.FAIL,
            f"{version_text} is unsupported; Python 3.12 or newer is required.",
        )
    return EnvironmentCheck(
        "Python",
        CheckStatus.PASS,
        f"{version_text} meets the requirement of Python 3.12 or newer.",
    )


def _command_check(
    name: str,
    args: list[str],
    *,
    success_detail: str,
    unavailable_detail: str,
    nonzero_detail: str,
    cwd: Path | None = None,
) -> EnvironmentCheck:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=CHECK_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return EnvironmentCheck(name, CheckStatus.WARN, unavailable_detail)
    except subprocess.TimeoutExpired:
        return EnvironmentCheck(
            name,
            CheckStatus.WARN,
            f"The {name.lower()} check timed out after {CHECK_TIMEOUT_SECONDS} seconds.",
        )
    except OSError:
        return EnvironmentCheck(
            name,
            CheckStatus.WARN,
            f"The {name.lower()} check could not be run.",
        )

    if result.returncode != 0:
        return EnvironmentCheck(name, CheckStatus.WARN, nonzero_detail)
    return EnvironmentCheck(name, CheckStatus.PASS, success_detail)


def inspect_environment() -> DoctorReport:
    """Check Python, local tools, and repository context without modifying them."""
    checks = (
        _python_check(),
        _command_check(
            "Git executable",
            ["git", "--version"],
            success_detail="Git is available.",
            unavailable_detail="Git was not found on PATH.",
            nonzero_detail="Git returned a nonzero status while checking its version.",
        ),
        _command_check(
            "uv executable",
            ["uv", "--version"],
            success_detail="uv is available.",
            unavailable_detail="uv was not found on PATH.",
            nonzero_detail="uv returned a nonzero status while checking its version.",
        ),
        _command_check(
            "Docker CLI",
            ["docker", "--version"],
            success_detail="Docker CLI is available; daemon status was not checked.",
            unavailable_detail="Docker CLI was not found on PATH.",
            nonzero_detail="Docker CLI returned a nonzero status while checking its version.",
        ),
        _command_check(
            "Git repository",
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
            success_detail="The current directory is inside a Git repository.",
            unavailable_detail="Cannot check the current directory because Git was not found.",
            nonzero_detail="The current directory is not inside a Git repository.",
        ),
    )
    return DoctorReport(checks)
