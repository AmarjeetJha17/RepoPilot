"""Linux integration tests for fixed verification over staged workspace copies."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from repopilot.sandbox.execution import (
    BackendExecution,
    ExecutionStatus,
    SandboxConfig,
    SandboxRequest,
    SandboxRunner,
    VerificationCommand,
)
from repopilot.sandbox.workspace import WorkspaceManager, workspace_identity_for_handle
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, ExecutionWorkspace

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Secure sandbox workspaces are Linux-only."
    ),
]


class FakeDockerBackend:
    async def create(self, spec):  # type: ignore[no-untyped-def]
        assert spec.image.endswith("@sha256:" + "c" * 64)
        assert spec.staging_root.name.startswith("repopilot-workspace-")
        assert spec.argv[0] == "python"
        return "c" * 64

    async def execute(self, container_id: str, max_runtime: float, output_limit: int):
        return BackendExecution(1, "", "syntax error")

    async def cleanup(self, container_id: str, max_runtime: float) -> bool:
        return True


def test_syntax_failure_is_distinct_and_source_remains_unchanged(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = source / "module.py"
    original = "VALUE = 1\n"
    target.write_text(original, encoding="utf-8")
    staging_parent = tmp_path / "staging-parent"
    staging_parent.mkdir()
    manager = WorkspaceManager(temp_root=staging_parent)
    handle = manager.prepare(source)
    authorization = AuthorizationContext(
        run_id="sandbox-integration",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.SANDBOX,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.SANDBOXED_TEST_EXECUTION}),
    )
    runner = SandboxRunner(
        manager,
        handle,
        authorization,
        SandboxConfig("example.invalid/repopilot@sha256:" + "c" * 64),
        FakeDockerBackend(),
    )
    try:
        result = asyncio.run(
            runner.run(SandboxRequest(VerificationCommand.PYTHON_SYNTAX, ("module.py",)))
        )

        assert result.status is ExecutionStatus.COMMAND_FAILED
        assert result.exit_code == 1
        assert result.cleanup.value == "removed"
        assert target.read_text(encoding="utf-8") == original
    finally:
        manager.cleanup(handle)
