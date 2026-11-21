"""Integration behavior for isolated copy-based repository workspaces."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from repopilot.sandbox.workspace import (
    IntegrityChangeKind,
    WorkspaceCleanupState,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceLimits,
    WorkspaceManager,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Secure no-atime descriptor-relative staging is supported on Linux only.",
    ),
]


def _source(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    (root / "src").mkdir(parents=True)
    (root / "src" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _manager(tmp_path: Path, *, limits: WorkspaceLimits | None = None) -> WorkspaceManager:
    staging_parent = tmp_path / "staging-parent"
    staging_parent.mkdir(exist_ok=True)
    return WorkspaceManager(temp_root=staging_parent, limits=limits)


def test_prepares_copy_with_stable_baseline_and_leaves_source_unchanged(tmp_path: Path) -> None:
    source = _source(tmp_path)
    original = (source / "src" / "module.py").read_bytes()
    manager = _manager(tmp_path)

    handle = manager.prepare(source)

    assert (handle.staging_root / "src" / "module.py").read_bytes() == original
    assert handle.baseline.files[0].path == "src/module.py"
    assert handle.baseline.files[0].size_bytes == len(original)
    assert handle.baseline.files[0].sha256 == hashlib.sha256(original).hexdigest()
    assert handle.baseline.file_count == 1
    assert handle.baseline.total_bytes == len(original)
    assert handle.staging_root.stat().st_mode & 0o777 == 0o700
    assert (handle.staging_root / "src" / "module.py").stat().st_mode & 0o777 == 0o600
    assert str(source) not in handle.baseline.to_json()
    assert (source / "src" / "module.py").read_bytes() == original
    manager.cleanup(handle)
    assert (source / "src" / "module.py").read_bytes() == original


def test_repeated_preparation_has_deterministic_manifest(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)

    first = manager.prepare(source)
    second = manager.prepare(source)

    assert first.baseline.to_json() == second.baseline.to_json()
    manager.cleanup(first)
    manager.cleanup(second)


def test_excludes_git_secrets_credentials_and_caches(tmp_path: Path) -> None:
    source = _source(tmp_path)
    for relative in (
        ".git/config",
        ".env",
        ".env.local",
        ".aws/credentials",
        "service_credentials.json",
        "local_password.txt",
        "access_token.txt",
        "private.pem",
        ".venv/pyvenv.cfg",
        "__pycache__/module.pyc",
        ".pytest_cache/state",
        ".mypy_cache/state",
        ".ruff_cache/state",
        ".uv-cache/state",
        "coverage.xml",
        ".coverage",
        "build/output.py",
        "dist/archive.zip",
        "logs/run.log",
    ):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic secret or cache", encoding="utf-8")

    manager = _manager(tmp_path)
    handle = manager.prepare(source)

    assert tuple(item.path for item in handle.baseline.files) == ("src/module.py",)
    assert not (handle.staging_root / ".env").exists()
    assert not (handle.staging_root / ".git").exists()
    manager.cleanup(handle)


def test_excludes_binary_files_by_type_and_content(tmp_path: Path) -> None:
    source = _source(tmp_path)
    (source / "image.png").write_bytes(b"synthetic image")
    (source / "late-binary.dat").write_bytes(b"x" * (64 * 1024) + b"\x00payload")
    manager = _manager(tmp_path)

    handle = manager.prepare(source)

    assert tuple(item.path for item in handle.baseline.files) == ("src/module.py",)
    assert not (handle.staging_root / "image.png").exists()
    assert not (handle.staging_root / "late-binary.dat").exists()
    manager.cleanup(handle)


def test_excludes_files_with_common_embedded_credential_patterns(tmp_path: Path) -> None:
    source = _source(tmp_path)
    credential_file = source / "settings.py"
    credential_file.write_text('API_KEY = "synthetic-value-123456789"\n', encoding="utf-8")
    manager = _manager(tmp_path)

    handle = manager.prepare(source)

    assert tuple(item.path for item in handle.baseline.files) == ("src/module.py",)
    assert not (handle.staging_root / "settings.py").exists()
    manager.cleanup(handle)


@pytest.mark.parametrize(
    ("limits", "relative", "content"),
    [
        (WorkspaceLimits(max_files=1), "other.py", "x"),
        (WorkspaceLimits(max_total_bytes=2), "other.py", "xxx"),
        (WorkspaceLimits(max_file_bytes=2), "other.py", "xxx"),
        (WorkspaceLimits(max_depth=1), "deep/nested/file.py", "x"),
    ],
)
def test_rejects_file_count_byte_and_depth_limit_violations(
    tmp_path: Path, limits: WorkspaceLimits, relative: str, content: str
) -> None:
    source = _source(tmp_path)
    target = source / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    manager = _manager(tmp_path, limits=limits)

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source)

    assert error.value.code is WorkspaceErrorCode.LIMIT_EXCEEDED
    assert not list((tmp_path / "staging-parent").iterdir())


def test_detects_modified_deleted_and_unexpected_files(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    handle = manager.prepare(source)
    (handle.staging_root / "src" / "module.py").write_text("changed", encoding="utf-8")
    (handle.staging_root / "new.py").write_text("new", encoding="utf-8")

    modified_and_unexpected = manager.check_integrity(handle)

    assert {change.kind for change in modified_and_unexpected.changes} == {
        IntegrityChangeKind.MODIFIED,
        IntegrityChangeKind.UNEXPECTED,
    }
    (handle.staging_root / "src" / "module.py").unlink()
    deleted = manager.check_integrity(handle)
    assert any(change.kind is IntegrityChangeKind.DELETED for change in deleted.changes)
    manager.cleanup(handle)


def test_detects_staged_symlink_substitution_without_following_it(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    manager = _manager(tmp_path)
    handle = manager.prepare(source)
    target = handle.staging_root / "src" / "module.py"
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError as error:
        manager.cleanup(handle)
        pytest.fail(f"Linux must support symlink creation for this security test: {error}")

    report = manager.check_integrity(handle)

    assert any(change.kind is IntegrityChangeKind.TYPE_CHANGED for change in report.changes)
    assert outside.read_text(encoding="utf-8") == "outside"
    manager.cleanup(handle)


def test_detects_baseline_file_replaced_by_directory(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    handle = manager.prepare(source)
    target = handle.staging_root / "src" / "module.py"
    target.unlink()
    target.mkdir()

    report = manager.check_integrity(handle)

    assert any(change.kind is IntegrityChangeKind.TYPE_CHANGED for change in report.changes)
    manager.cleanup(handle)


@pytest.mark.parametrize(
    "limits",
    [WorkspaceLimits(max_files=1), WorkspaceLimits(max_total_bytes=12)],
)
def test_integrity_check_reports_staging_limit_violations(
    tmp_path: Path, limits: WorkspaceLimits
) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path, limits=limits)
    handle = manager.prepare(source)
    (handle.staging_root / "new.py").write_text("unexpected", encoding="utf-8")

    report = manager.check_integrity(handle)

    assert any(change.kind is IntegrityChangeKind.LIMIT_EXCEEDED for change in report.changes)
    manager.cleanup(handle)


def test_cleanup_is_idempotent_and_rejects_substituted_handle(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    handle = manager.prepare(source)

    with pytest.raises(WorkspaceError) as error:
        manager.cleanup(replace(handle, staging_root=tmp_path / "not-owned"))
    assert error.value.code is WorkspaceErrorCode.OWNERSHIP_MISMATCH
    assert handle.staging_root.exists()
    assert manager.cleanup(handle) is WorkspaceCleanupState.CLEANED
    assert manager.cleanup(handle) is WorkspaceCleanupState.CLEANED


def test_manager_cleans_workspace_when_context_exits_with_exception(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    handle = None

    with pytest.raises(RuntimeError, match="synthetic failure"), manager:
        handle = manager.prepare(source)
        raise RuntimeError("synthetic failure")

    assert handle is not None
    assert not handle.staging_root.exists()
    assert manager.cleanup_state(handle) is WorkspaceCleanupState.CLEANED


def test_rejects_staging_parent_inside_source(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(temp_root=source / "staging")

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source)

    assert error.value.code is WorkspaceErrorCode.DESTINATION_UNSAFE
    assert not (source / "staging").exists()


def test_rejects_symlinked_staging_parent(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "staging-link"
    try:
        destination.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.fail(f"Linux must support symlink creation for this security test: {error}")
    manager = WorkspaceManager(temp_root=destination)

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source)

    assert error.value.code is WorkspaceErrorCode.DESTINATION_UNSAFE
    assert not list(outside.iterdir())


def test_rejects_source_changes_during_copy_and_removes_partial_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    import repopilot.sandbox.workspace as workspace_module

    original_write = workspace_module._write_all
    changed = False

    def mutate_while_copying(descriptor: int, content: bytes) -> None:
        nonlocal changed
        original_write(descriptor, content)
        if not changed:
            changed = True
            (source / "src" / "module.py").write_text("changed during copy", encoding="utf-8")

    monkeypatch.setattr(workspace_module, "_write_all", mutate_while_copying)

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source)

    assert error.value.code is WorkspaceErrorCode.SOURCE_CHANGED
    assert not list((tmp_path / "staging-parent").iterdir())


def test_cleanup_after_copy_interruption_removes_partial_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    import repopilot.sandbox.workspace as workspace_module

    def interrupt(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise KeyboardInterrupt

    monkeypatch.setattr(workspace_module, "_copy_regular_file", interrupt)

    with pytest.raises(KeyboardInterrupt):
        manager.prepare(source)

    assert not list((tmp_path / "staging-parent").iterdir())


def test_rejects_source_symlink_and_unsupported_fifo(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)
    source_link = tmp_path / "source-link"
    try:
        source_link.symlink_to(source, target_is_directory=True)
    except OSError as error:
        pytest.fail(f"Linux must support symlink creation for this security test: {error}")

    with pytest.raises(WorkspaceError) as root_error:
        manager.prepare(source_link)
    assert root_error.value.code is WorkspaceErrorCode.SOURCE_ROOT_INVALID

    if hasattr(os, "mkfifo"):
        os.mkfifo(source / "pipe")
        with pytest.raises(WorkspaceError) as file_error:
            manager.prepare(source)
        assert file_error.value.code is WorkspaceErrorCode.UNSUPPORTED_ENTRY


def test_rejects_path_traversal_source_root(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = _manager(tmp_path)

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source / ".." / "source")

    assert error.value.code is WorkspaceErrorCode.SOURCE_ROOT_INVALID


@pytest.mark.parametrize("name", ["con.txt", "bad?name.py", "trailing. "])
def test_rejects_nonportable_source_names(tmp_path: Path, name: str) -> None:
    source = _source(tmp_path)
    (source / name).write_text("synthetic", encoding="utf-8")
    manager = _manager(tmp_path)

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source)

    assert error.value.code is WorkspaceErrorCode.UNSUPPORTED_ENTRY


def test_cleanup_does_not_follow_replacement_of_staging_root(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    manager = _manager(tmp_path)
    handle = manager.prepare(source)
    manager.cleanup_state(handle)
    manager_root = handle.staging_root

    # The open manager handle still owns the original directory; a replacement link is not owned.
    manager_root.rename(tmp_path / "renamed-workspace")
    try:
        manager_root.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        (tmp_path / "renamed-workspace").rename(manager_root)
        manager.cleanup(handle)
        pytest.fail(f"Linux must support symlink creation for this security test: {error}")

    with pytest.raises(WorkspaceError) as error:
        manager.cleanup(handle)

    assert error.value.code is WorkspaceErrorCode.CLEANUP_FAILED
    assert manager.cleanup_state(handle) is WorkspaceCleanupState.FAILED
    assert marker.read_text(encoding="utf-8") == "keep"
    manager_root.unlink()
    (tmp_path / "renamed-workspace").rename(manager_root)
    assert manager.cleanup(handle) is WorkspaceCleanupState.CLEANED
