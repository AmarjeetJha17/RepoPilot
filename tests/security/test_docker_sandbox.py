"""Linux trust-boundary checks for the policy-gated Docker runner."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from repopilot.sandbox.execution import (
    BackendExecution,
    CleanupStatus,
    ContainerSpec,
    ExecutionStatus,
    SandboxConfig,
    SandboxLimits,
    SandboxRequest,
    SandboxRunner,
    VerificationCommand,
)
from repopilot.sandbox.workspace import (
    WorkspaceHandle,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, ExecutionWorkspace

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Secure sandbox workspaces are Linux-only."
    ),
]


class FakeBackend:
    def __init__(self, result: BackendExecution | None = None, *, cleanup_ok: bool = True) -> None:
        self.result = result or BackendExecution(0, "verified", "")
        self.cleanup_ok = cleanup_ok
        self.created = 0
        self.cleaned: list[str] = []
        self.spec: ContainerSpec | None = None

    async def create(self, spec: ContainerSpec) -> str:
        self.created += 1
        self.spec = spec
        return "a" * 64

    async def execute(
        self, container_id: str, max_runtime: float, output_limit: int
    ) -> BackendExecution:
        return self.result

    async def cleanup(self, container_id: str, max_runtime: float) -> bool:
        self.cleaned.append(container_id)
        return self.cleanup_ok


def _runner(
    tmp_path: Path,
    backend: FakeBackend,
    *,
    allowed: bool = True,
    limits: SandboxLimits | None = None,
) -> tuple[WorkspaceManager, WorkspaceHandle, SandboxRunner, Path]:
    source = tmp_path / "source"
    source.mkdir()
    original = source / "module.py"
    original.write_text("VALUE = 1\n", encoding="utf-8")
    staging_parent = tmp_path / "staging-parent"
    staging_parent.mkdir()
    manager = WorkspaceManager(temp_root=staging_parent)
    handle = manager.prepare(source)
    capabilities = frozenset({Capability.SANDBOXED_TEST_EXECUTION}) if allowed else frozenset()
    context = AuthorizationContext(
        run_id="sandbox-test",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.SANDBOX,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=capabilities,
    )
    runner = SandboxRunner(
        manager,
        handle,
        context,
        SandboxConfig("example.invalid/repopilot@sha256:" + "b" * 64),
        backend,
        limits=limits or SandboxLimits(),
    )
    return manager, handle, runner, original


def test_authorized_execution_uses_read_only_staging_and_cleans_owned_container(
    tmp_path: Path,
) -> None:
    backend = FakeBackend()
    manager, handle, runner, original = _runner(tmp_path, backend)
    try:
        result = asyncio.run(
            runner.run(SandboxRequest(VerificationCommand.PYTHON_SYNTAX, ("module.py",)))
        )

        assert result.status is ExecutionStatus.PASSED
        assert result.real_container is False
        assert result.isolation_inspected is False
        assert result.image_digest is None
        assert result.cleanup is CleanupStatus.REMOVED
        assert backend.cleaned == ["a" * 64]
        assert backend.spec is not None
        assert backend.spec.staging_root == handle.staging_root
        assert original.read_text(encoding="utf-8") == "VALUE = 1\n"
        assert "--" not in backend.spec.argv
        assert "shell=True" not in backend.spec.argv
    finally:
        manager.cleanup(handle)


def test_policy_denial_never_creates_or_executes_container(tmp_path: Path) -> None:
    backend = FakeBackend()
    manager, handle, runner, _ = _runner(tmp_path, backend, allowed=False)
    try:
        result = asyncio.run(
            runner.run(SandboxRequest(VerificationCommand.PYTHON_SYNTAX, ("module.py",)))
        )

        assert result.status is ExecutionStatus.DENIED
        assert backend.created == 0
        assert not backend.cleaned
    finally:
        manager.cleanup(handle)


def test_output_limit_and_cleanup_failure_are_explicit(tmp_path: Path) -> None:
    backend = FakeBackend(BackendExecution(0, "bounded", "", truncated=True), cleanup_ok=False)
    manager, handle, runner, _ = _runner(tmp_path, backend)
    try:
        result = asyncio.run(
            runner.run(SandboxRequest(VerificationCommand.PYTHON_SYNTAX, ("module.py",)))
        )

        assert result.status is ExecutionStatus.CLEANUP_FAILED
        assert result.output_truncated
        assert result.cleanup is CleanupStatus.FAILED
    finally:
        manager.cleanup(handle)


def test_pre_cancelled_run_has_no_execution_side_effects(tmp_path: Path) -> None:
    backend = FakeBackend()
    manager, handle, runner, _ = _runner(tmp_path, backend)
    cancellation = asyncio.Event()
    cancellation.set()
    try:
        result = asyncio.run(
            runner.run(
                SandboxRequest(VerificationCommand.PYTEST, ("module.py",)),
                cancellation=cancellation,
            )
        )

        assert result.status is ExecutionStatus.CANCELLED
        assert backend.created == 0
    finally:
        manager.cleanup(handle)


def test_runtime_timeout_cleans_the_owned_container(tmp_path: Path) -> None:
    class SlowBackend(FakeBackend):
        async def execute(
            self, container_id: str, max_runtime: float, output_limit: int
        ) -> BackendExecution:
            await asyncio.sleep(5)
            return BackendExecution(0, "", "")

    backend = SlowBackend()
    manager, handle, runner, _ = _runner(tmp_path, backend, limits=SandboxLimits(timeout_seconds=1))
    try:
        result = asyncio.run(
            runner.run(SandboxRequest(VerificationCommand.PYTHON_SYNTAX, ("module.py",)))
        )

        assert result.status is ExecutionStatus.TIMED_OUT
        assert result.cleanup is CleanupStatus.REMOVED
        assert backend.cleaned == ["a" * 64]
    finally:
        manager.cleanup(handle)


def test_external_cancellation_drains_execution_with_event_and_cleans_container(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()

    class WaitingBackend(FakeBackend):
        async def execute(self, container_id, max_runtime, output_limit):
            entered.set()
            await asyncio.Event().wait()

    backend = WaitingBackend()
    manager, handle, runner, _ = _runner(tmp_path, backend)

    async def scenario():
        task = asyncio.create_task(
            runner.run(
                SandboxRequest(VerificationCommand.PYTEST, ("module.py",)),
                cancellation=asyncio.Event(),
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    try:
        asyncio.run(scenario())
        assert backend.cleaned == ["a" * 64]
    finally:
        manager.cleanup(handle)
