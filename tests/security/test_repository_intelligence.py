"""Filesystem-boundary tests for repository intelligence."""

from __future__ import annotations

import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from repopilot.context import IntelligenceError, IntelligenceErrorCode, RepositoryIntelligence
from repopilot.sandbox.workspace import WorkspaceHandle, WorkspaceManager
from tests.fixtures.repository_intelligence import create_repository

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux workspace boundary."),
]


def _prepared(tmp_path: Path) -> tuple[WorkspaceManager, Path, WorkspaceHandle]:
    source, _files = create_repository(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    manager = WorkspaceManager(temp_root=staging)
    handle = manager.prepare(source)
    return manager, source, handle


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "pkg/../../outside",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "\\\\server\\share\\file",
        "pkg\\first.py",
    ],
)
def test_rejects_traversal_absolute_drive_unc_and_backslash_paths(
    tmp_path: Path, path: str
) -> None:
    manager, _source, handle = _prepared(tmp_path)
    service = RepositoryIntelligence(manager, handle)

    with pytest.raises(IntelligenceError) as error:
        service.read_text(path)

    assert error.value.code is IntelligenceErrorCode.INVALID_PATH
    assert str(error.value) == "Repository intelligence operation failed: invalid_path."
    manager.close()


def test_rejects_foreign_and_cleaned_workspace_handles(tmp_path: Path) -> None:
    manager, source, handle = _prepared(tmp_path)
    other = WorkspaceManager(temp_root=tmp_path / "staging")
    with pytest.raises(IntelligenceError) as foreign:
        RepositoryIntelligence(other, handle)
    assert foreign.value.code is IntelligenceErrorCode.WORKSPACE_UNAVAILABLE

    manager.cleanup(handle)
    with pytest.raises(IntelligenceError) as cleaned:
        RepositoryIntelligence(manager, handle)
    assert cleaned.value.code is IntelligenceErrorCode.WORKSPACE_UNAVAILABLE
    assert (source / "pkg/first.py").exists()


def test_rejects_equal_but_forged_handle_copy(tmp_path: Path) -> None:
    manager, _source, handle = _prepared(tmp_path)
    forged = replace(handle)
    assert forged == handle
    assert forged is not handle

    with pytest.raises(IntelligenceError) as error:
        RepositoryIntelligence(manager, forged)

    assert error.value.code is IntelligenceErrorCode.WORKSPACE_UNAVAILABLE
    manager.close()


def test_read_rejects_staged_symlink_without_following_external_target(tmp_path: Path) -> None:
    manager, _source, handle = _prepared(tmp_path)
    target = tmp_path / "outside-secret.txt"
    target.write_text("synthetic outside secret", encoding="utf-8")
    staged_file = handle.staging_root / "pkg/first.py"
    staged_file.unlink()
    staged_file.symlink_to(target)
    service = RepositoryIntelligence(manager, handle)

    with pytest.raises(IntelligenceError) as error:
        service.read_text("pkg/first.py")

    assert error.value.code is IntelligenceErrorCode.UNSUPPORTED_ENTRY
    assert str(target) not in str(error.value)
    assert "synthetic outside secret" not in str(error.value)
    assert target.read_text(encoding="utf-8") == "synthetic outside secret"
    manager.close()


def test_read_rejects_replaced_directory_symlink(tmp_path: Path) -> None:
    manager, _source, handle = _prepared(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("synthetic outside secret", encoding="utf-8")
    staged_package = handle.staging_root / "pkg"
    staged_package.rename(handle.staging_root / "saved-pkg")
    staged_package.symlink_to(outside, target_is_directory=True)
    service = RepositoryIntelligence(manager, handle)

    with pytest.raises(IntelligenceError) as error:
        service.read_text("pkg/secret.py")

    assert error.value.code is IntelligenceErrorCode.UNSUPPORTED_ENTRY
    assert str(outside) not in str(error.value)
    assert secret.read_text(encoding="utf-8") == "synthetic outside secret"
    manager.close()


def test_intelligence_does_not_use_network_or_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manager, _source, handle = _prepared(tmp_path)
    service = RepositoryIntelligence(manager, handle)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Repository intelligence must remain local and read-only.")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert service.discover_files().files
    assert service.search_literal("needle").matches
    manager.close()
