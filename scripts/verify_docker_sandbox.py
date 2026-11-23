"""Operator-only fixed synthetic checks; no image provisioning or arbitrary task input."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory

from repopilot.sandbox.docker_backend import (
    DockerCliBackend,
    ReadinessStatus,
    diagnose_docker,
)
from repopilot.sandbox.execution import (
    CleanupStatus,
    ExecutionStatus,
    SandboxConfig,
    SandboxLimits,
    SandboxRequest,
    SandboxRunner,
    VerificationCommand,
)
from repopilot.sandbox.workspace import (
    WorkspaceError,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, ExecutionWorkspace

_READONLY_TEST = """from pathlib import Path
import pytest

def test_readonly():
    assert Path('/workspace/check.py').read_bytes()
    with pytest.raises(OSError):
        Path('/workspace/check.py').write_text('changed')
    with pytest.raises(OSError):
        Path('/root-write-probe').write_text('changed')
    status = Path('/proc/self/status').read_text()
    assert 'NoNewPrivs:\\t1' in status
    assert 'Seccomp:\\t2' in status
    assert 'CapEff:\\t0000000000000000' in status
    assert not Path('/var/run/docker.sock').exists()
    routes = Path('/proc/net/route').read_text().splitlines()
    assert len(routes) == 1
"""


async def verify(config: SandboxConfig, *, smoke: bool) -> dict[str, object]:
    """Create only disposable fixtures; return safe metadata without subprocess output."""
    with TemporaryDirectory(prefix="repopilot-docker-verification-") as temporary:
        root = Path(temporary)
        readiness = await diagnose_docker(config, root)
        report: dict[str, object] = {"preflight": asdict(readiness), "real_tests": "NOT_RUN"}
        if readiness.status is not ReadinessStatus.READY or not smoke:
            return report
        scenarios = (
            (
                "syntax_pass",
                "VALUE = 1\n",
                VerificationCommand.PYTHON_SYNTAX,
                ExecutionStatus.PASSED,
                30,
            ),
            (
                "syntax_fail",
                "def broken(:\n",
                VerificationCommand.PYTHON_SYNTAX,
                ExecutionStatus.COMMAND_FAILED,
                30,
            ),
            (
                "pytest_pass",
                "def test_pass():\n    assert 1 == 1\n",
                VerificationCommand.PYTEST,
                ExecutionStatus.PASSED,
                30,
            ),
            (
                "pytest_fail",
                "def test_fail():\n    assert False\n",
                VerificationCommand.PYTEST,
                ExecutionStatus.COMMAND_FAILED,
                30,
            ),
            (
                "timeout",
                "import time\ndef test_slow():\n    time.sleep(60)\n",
                VerificationCommand.PYTEST,
                ExecutionStatus.TIMED_OUT,
                3,
            ),
            ("readonly", _READONLY_TEST, VerificationCommand.PYTEST, ExecutionStatus.PASSED, 30),
        )
        outcomes: list[dict[str, object]] = []
        for name, content, command, expected, timeout in scenarios:
            source, staging = root / name, root / (name + "-staging")
            source.mkdir()
            staging.mkdir()
            original = content.encode("utf-8")
            (source / "check.py").write_bytes(original)
            with WorkspaceManager(temp_root=staging) as manager:
                handle = manager.prepare(source)
                authorization = AuthorizationContext(
                    "operator-smoke",
                    handle.staging_root,
                    ExecutionWorkspace.SANDBOX,
                    workspace_identity_for_handle(handle),
                    frozenset({Capability.SANDBOXED_TEST_EXECUTION}),
                )
                runner = SandboxRunner(
                    manager,
                    handle,
                    authorization,
                    config,
                    DockerCliBackend(),
                    limits=SandboxLimits(timeout_seconds=timeout),
                )
                result = await runner.run(SandboxRequest(command, ("check.py",)))
                unchanged = (
                    manager.check_integrity(handle).matches_baseline
                    and (source / "check.py").read_bytes() == original
                )
                ok = (
                    result.status is expected
                    and result.cleanup is CleanupStatus.REMOVED
                    and unchanged
                )
                if expected is ExecutionStatus.PASSED:
                    ok = ok and result.real_container and result.isolation_inspected
                outcomes.append(
                    {
                        "scenario": name,
                        "expected_status": expected.value,
                        "status": result.status.value,
                        "exit_code": result.exit_code,
                        "container_removed": result.cleanup is CleanupStatus.REMOVED,
                        "container_created": result.cleanup is not CleanupStatus.NOT_CREATED,
                        "isolation_inspected": result.isolation_inspected,
                        "real_command_observed": result.real_container,
                        "runtime_readonly_verified": name == "readonly" and ok,
                        "workspace_sha256": hashlib.sha256(original).hexdigest(),
                        "execution_workspace_sha256": result.workspace_sha256,
                        "image_digest": config.image.split("@")[1],
                        "unchanged": unchanged,
                        "ok": ok,
                    }
                )
                if not ok:
                    break  # Do not continue after a security or cleanup failure.
        report["scenarios"] = outcomes
        report["real_tests"] = (
            "PASS" if len(outcomes) == 6 and all(item["ok"] for item in outcomes) else "FAIL"
        )
        report["independent_coding_task_verification"] = False
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", required=True, help="Reviewed, locally provisioned repo@sha256 digest"
    )
    parser.add_argument(
        "--smoke", action="store_true", help="Explicitly create synthetic containers"
    )
    args = parser.parse_args()
    try:
        config = SandboxConfig(args.image)
        if not sys.platform.startswith("linux"):
            report: dict[str, object] = {
                "preflight": {"status": "NOT_READY", "reason": "platform_unsupported"},
                "real_tests": "NOT_RUN",
            }
        else:
            report = asyncio.run(verify(config, smoke=args.smoke))
    except (ValueError, OSError, RuntimeError, WorkspaceError):
        report = {
            "preflight": {"status": "NOT_READY", "reason": "verification_unavailable"},
            "real_tests": "NOT_RUN",
        }
    print(json.dumps(report, sort_keys=True))
    return (
        0
        if report.get("real_tests") == "PASS"
        or (
            not args.smoke
            and isinstance(report.get("preflight"), dict)
            and report["preflight"].get("status") == "READY"
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
