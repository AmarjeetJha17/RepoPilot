"""Linux integration tests for the existing-services coding-task coordinator."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

import repopilot.application.coding_task_demo as demo
from repopilot.agent.budget import BudgetConfig
from repopilot.providers.base import ProviderUnavailableError
from repopilot.sandbox.execution import (
    ExecutionResult,
    ExecutionStatus,
    SandboxConfig,
    SandboxRequest,
    SandboxRunner,
    VerificationCommand,
)
from repopilot.sandbox.patches import PatchFailure, PatchStagingResult, PatchStagingStatus

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Manager-owned workspace is Linux-only."
    ),
]


def test_provider_failure_stops_before_patch_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        demo,
        "_new_investigation_provider",
        lambda: demo._CapturingMockProvider((ProviderUnavailableError(),)),
    )

    result = asyncio.run(demo.run_coding_task_demo(temp_parent=tmp_path))

    assert result.failure_code == "provider_failure"
    assert result.model_requests == 1
    assert result.staging_status == "not_started"
    assert result.source_repository_unchanged is True
    assert result.live_application_enabled is False


def test_tool_budget_exhaustion_stops_before_patch_staging(tmp_path: Path) -> None:
    result = asyncio.run(
        demo.run_coding_task_demo(
            temp_parent=tmp_path,
            budget_limits=BudgetConfig(
                max_model_requests=1,
                max_run_seconds=60,
                max_tool_calls_per_response=2,
                max_total_tool_calls=4,
            ),
        )
    )

    assert result.failure_code == "model_tool_budget_exhausted"
    assert result.model_requests == 1
    assert result.staging_status == "not_started"
    assert result.source_repository_unchanged is True


def test_stale_patch_hash_is_reported_without_claiming_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def stale(_stager: object, _proposal: object) -> PatchStagingResult:
        return PatchStagingResult(PatchStagingStatus.FAILED, reason=PatchFailure.SOURCE_CHANGED)

    monkeypatch.setattr(demo.PatchStager, "stage", stale)

    result = asyncio.run(demo.run_coding_task_demo(temp_parent=tmp_path))

    assert result.failure_code == "stale_patch_hash"
    assert result.staging_status == "failed"
    assert result.changed_files == ()
    assert result.after_sha256 is None
    assert result.source_repository_unchanged is True


def test_cancellation_returns_a_safe_result_and_cleans_owned_workspace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    started = asyncio.Event()

    class BlockingProvider(demo._CapturingMockProvider):
        async def next_action(self, request: demo.ModelRequest) -> demo.ModelResponse:
            self.requests.append(request)
            started.set()
            await asyncio.Event().wait()

    provider = BlockingProvider(())
    monkeypatch.setattr(demo, "_new_investigation_provider", lambda: provider)

    async def run_and_cancel() -> demo.CodingTaskDemoReport:
        task = asyncio.create_task(demo.run_coding_task_demo(temp_parent=tmp_path))
        await started.wait()
        task.cancel()
        return await task

    result = asyncio.run(run_and_cancel())

    assert result.outcome == "cancelled"
    assert result.failure_code == "investigation_cancelled"
    assert result.staging_status == "not_started"
    assert result.workspace_cleanup == "cleaned"
    assert result.source_repository_unchanged is True


def test_missing_docker_runtime_is_not_reported_as_a_test_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def missing_runtime(*_args: object, **_kwargs: object) -> str:
        raise FileNotFoundError("docker executable is unavailable")

    monkeypatch.setattr(demo.DockerCliBackend, "create", missing_runtime)
    image = "example.invalid/repopilot@sha256:" + "c" * 64
    assert SandboxConfig(image).image == image

    result = asyncio.run(
        demo.run_coding_task_demo(
            temp_parent=tmp_path,
            run_sandbox_tests=True,
            docker_image=image,
        )
    )

    assert result.sandbox_status == "infrastructure_error"
    assert result.sandbox_tests == "NOT_RUN"
    assert result.independent_verification is False


def test_stub_sandbox_pass_is_not_independent_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def passed(
        _runner: SandboxRunner, request: SandboxRequest, **_kwargs: object
    ) -> ExecutionResult:
        assert request == SandboxRequest(VerificationCommand.PYTEST, ("tests/test_first_item.py",))
        return ExecutionResult(
            "synthetic-execution", VerificationCommand.PYTEST, ExecutionStatus.PASSED, 0, 0.1
        )

    monkeypatch.setattr(demo.SandboxRunner, "run", passed)
    image = "example.invalid/repopilot@sha256:" + "d" * 64

    result = asyncio.run(
        demo.run_coding_task_demo(
            temp_parent=tmp_path,
            run_sandbox_tests=True,
            docker_image=image,
        )
    )

    assert result.sandbox_tests == "PASS"
    assert result.sandbox_status == "passed"
    assert result.outcome == "sandbox_passed"
    assert result.independent_verification is False  # A stub result is not real execution evidence.
