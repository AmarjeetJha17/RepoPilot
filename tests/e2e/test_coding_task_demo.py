"""Linux end-to-end acceptance tests for the staged coding-task demonstration."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from repopilot.application.coding_task_demo import run_coding_task_demo

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Manager-owned workspace is Linux-only."
    ),
]

BASELINE_SHA256 = "3210aac3b1b3a4d67f2adaebf97c2fa17cac17a42ac35b601667365b45f0afbb"


def test_offline_coding_task_stages_known_patch_with_accurate_evidence(
    tmp_path: Path,
) -> None:
    result = asyncio.run(run_coding_task_demo(temp_parent=tmp_path))

    assert result.task_id == "empty-input-returns-empty-string"
    assert result.synthetic_repository_id == "synthetic-empty-input-v1"
    assert result.model_provider == "offline-mock"
    assert result.model_requests == 2
    assert result.read_only_tools_executed == ("repo_read_text",)
    assert result.tool_call_id == "coding-demo-read-1"
    assert result.tool_result_status == "success"
    assert result.feedback_correlated is True
    assert result.patch_provenance == "deterministic-fixture"
    assert result.staging_status == "staged"
    assert result.changed_files == ("src/first_item.py",)
    assert result.baseline_sha256 == BASELINE_SHA256
    assert result.after_sha256 is not None and result.after_sha256 != BASELINE_SHA256
    assert "a/src/first_item.py" in result.diff
    assert "b/src/first_item.py" in result.diff
    assert result.source_repository_unchanged is True
    assert result.static_checks == ("python_ast_parse_passed",)
    assert result.fixture_check == "PASS"
    assert result.sandbox_tests == "NOT_RUN"
    assert result.live_application_enabled is False
    assert result.approval_requested is False
    assert result.independent_verification is False


def test_coding_task_demo_output_is_deterministic_bounded_and_redacted(
    tmp_path: Path,
) -> None:
    from repopilot.application.coding_task_demo import render_coding_task_demo

    result = asyncio.run(run_coding_task_demo(temp_parent=tmp_path))
    rendered = render_coding_task_demo(result)

    assert len(result.diff.encode("utf-8")) <= 12_000
    assert str(tmp_path) not in rendered
    assert "offline-mock" in rendered
    assert "independent_verification: false" in rendered
    assert "sandbox_tests: NOT_RUN" in rendered
    assert "NOT_RUN" in result.to_json()


def test_default_demo_does_not_attempt_docker_or_host_test_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from repopilot.sandbox.docker_backend import DockerCliBackend

    async def reject_docker(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("Docker is opt-in for this demonstration.")

    monkeypatch.setattr(DockerCliBackend, "create", reject_docker)
    result = asyncio.run(run_coding_task_demo(temp_parent=tmp_path))

    assert result.sandbox_tests == "NOT_RUN"
    assert result.sandbox_status == "not_requested"
