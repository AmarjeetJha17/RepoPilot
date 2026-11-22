"""Linux integration tests for policy-gated staged patch replacement."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from repopilot.application.patch_staging import PatchStager
from repopilot.sandbox.patches import (
    FileReplacement,
    PatchFailure,
    PatchLimits,
    PatchProposal,
    PatchStagingStatus,
)
from repopilot.sandbox.workspace import (
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, ExecutionWorkspace

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Secure patch staging is Linux-only."
    ),
]


def _workspace(tmp_path: Path, *, allowed: bool = True, limits: PatchLimits | None = None):
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "one.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "src" / "two.py").write_text("VALUE = 10\n", encoding="utf-8")
    (tmp_path / "staging").mkdir()
    manager = WorkspaceManager(temp_root=tmp_path / "staging")
    handle = manager.prepare(source)
    capabilities = frozenset({Capability.STAGED_FILE_MODIFICATION}) if allowed else frozenset()
    context = AuthorizationContext(
        run_id="synthetic-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=capabilities,
    )
    return (
        source,
        manager,
        handle,
        PatchStager(manager, handle, context, limits=limits or PatchLimits()),
    )


def _replacement(path: str, before: bytes, after: str) -> FileReplacement:
    return FileReplacement(
        path=path,
        operation="replace_text",
        expected_sha256=hashlib.sha256(before).hexdigest(),
        content=after,
    )


def test_stages_multiple_replacements_and_keeps_source_unchanged(tmp_path: Path) -> None:
    source, manager, handle, stager = _workspace(tmp_path)
    proposal = PatchProposal(
        replacements=(
            _replacement("src/two.py", b"VALUE = 10\n", "VALUE = 20\n"),
            _replacement("src/one.py", b"VALUE = 1\n", "VALUE = 2\n"),
        )
    )

    result = stager.stage(proposal)

    assert result.status is PatchStagingStatus.STAGED
    assert tuple(item.path for item in result.applied) == ("src/one.py", "src/two.py")
    assert (handle.staging_root / "src" / "one.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    assert (handle.staging_root / "src" / "two.py").read_text(encoding="utf-8") == "VALUE = 20\n"
    assert (source / "src" / "one.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert stager.compare_to_baseline().changed_paths == ("src/one.py", "src/two.py")
    manager.cleanup(handle)


def test_stale_hash_and_policy_denial_fail_before_any_replacement(tmp_path: Path) -> None:
    _, manager, handle, stager = _workspace(tmp_path)
    stale = PatchProposal(
        replacements=(
            FileReplacement(
                path="src/one.py",
                operation="replace_text",
                expected_sha256="0" * 64,
                content="VALUE = 2\n",
            ),
        )
    )
    stale_result = stager.stage(stale)
    assert stale_result.status is PatchStagingStatus.FAILED
    assert stale_result.reason is PatchFailure.SOURCE_CHANGED
    assert (handle.staging_root / "src" / "one.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    manager.cleanup(handle)

    _, denied_manager, denied_handle, denied_stager = _workspace(tmp_path / "denied", allowed=False)
    proposal = PatchProposal(
        replacements=(_replacement("src/one.py", b"VALUE = 1\n", "VALUE = 2\n"),)
    )
    denied = denied_stager.stage(proposal)
    assert denied.status is PatchStagingStatus.FAILED
    assert denied.reason is PatchFailure.POLICY_DENIED
    assert (denied_handle.staging_root / "src" / "one.py").read_text(
        encoding="utf-8"
    ) == "VALUE = 1\n"
    denied_manager.cleanup(denied_handle)


def test_batch_preflight_prevents_earlier_file_write_when_later_hash_is_stale(
    tmp_path: Path,
) -> None:
    _, manager, handle, stager = _workspace(tmp_path)
    proposal = PatchProposal(
        replacements=(
            _replacement("src/one.py", b"VALUE = 1\n", "VALUE = 2\n"),
            _replacement("src/two.py", b"wrong\n", "VALUE = 20\n"),
        )
    )

    result = stager.stage(proposal)

    assert result.reason is PatchFailure.SOURCE_CHANGED
    assert (handle.staging_root / "src" / "one.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert (handle.staging_root / "src" / "two.py").read_text(encoding="utf-8") == "VALUE = 10\n"
    manager.cleanup(handle)


def test_later_write_failure_reports_already_staged_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, manager, handle, stager = _workspace(tmp_path)
    original_replace = stager._writer.replace_bytes
    calls = 0

    def fail_second(*args: object, **kwargs: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise WorkspaceError(WorkspaceErrorCode.STAGING_FAILED)
        return original_replace(*args, **kwargs)

    monkeypatch.setattr(stager._writer, "replace_bytes", fail_second)
    proposal = PatchProposal(
        replacements=(
            _replacement("src/one.py", b"VALUE = 1\n", "VALUE = 2\n"),
            _replacement("src/two.py", b"VALUE = 10\n", "VALUE = 20\n"),
        )
    )

    result = stager.stage(proposal)

    assert result.status is PatchStagingStatus.PARTIAL
    assert tuple(item.path for item in result.applied) == ("src/one.py",)
    assert (handle.staging_root / "src" / "one.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    assert (handle.staging_root / "src" / "two.py").read_text(encoding="utf-8") == "VALUE = 10\n"
    manager.cleanup(handle)


def test_preview_is_relative_deterministic_bounded_and_control_sanitized(tmp_path: Path) -> None:
    _, manager, handle, stager = _workspace(tmp_path)
    proposal = PatchProposal(
        replacements=(_replacement("src/one.py", b"VALUE = 1\n", "VALUE = '\x1b[31m'\n"),)
    )
    assert stager.stage(proposal).status is PatchStagingStatus.STAGED

    preview = stager.generate_diff()

    assert "a/src/one.py" in preview.text
    assert "\\x1b[31m" in preview.text
    assert "\x1b" not in preview.text
    assert str(handle.source_root) not in preview.text
    assert preview == stager.generate_diff()
    manager.cleanup(handle)


def test_unregistered_sensitive_path_is_rejected_without_file_creation(tmp_path: Path) -> None:
    _, manager, handle, stager = _workspace(tmp_path)
    proposal = PatchProposal(replacements=(_replacement(".env", b"", "SECRET=never\n"),))

    result = stager.stage(proposal)

    assert result.status is PatchStagingStatus.FAILED
    assert result.reason is PatchFailure.PATH_NOT_ELIGIBLE
    assert not (handle.staging_root / ".env").exists()
    manager.cleanup(handle)


def test_duplicate_paths_fail_validation_and_diff_output_is_explicitly_bounded(
    tmp_path: Path,
) -> None:
    _, manager, handle, stager = _workspace(
        tmp_path, limits=PatchLimits(max_diff_bytes=8, max_diff_lines=2)
    )
    replacement = _replacement("src/one.py", b"VALUE = 1\n", "VALUE = 2\n")
    duplicate = PatchProposal(replacements=(replacement, replacement))

    assert not stager.validate_proposal(duplicate).valid
    assert (
        stager.stage(PatchProposal(replacements=(replacement,))).status is PatchStagingStatus.STAGED
    )
    preview = stager.generate_diff()

    assert preview.truncated is True
    assert preview.total_bytes > len(preview.text.encode("utf-8"))
    assert len(preview.text.encode("utf-8")) <= 8
    manager.cleanup(handle)
