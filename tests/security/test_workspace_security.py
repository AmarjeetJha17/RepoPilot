"""Trust-boundary checks for source isolation and manager-owned cleanup."""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

from repopilot.sandbox.workspace import (
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceManager,
)

pytestmark = pytest.mark.security


def test_source_symlink_is_rejected_without_reading_external_target(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "private.txt"
    secret.write_text("synthetic secret", encoding="utf-8")
    try:
        (source / "external.py").symlink_to(secret)
    except OSError as error:
        if sys.platform.startswith("linux"):
            pytest.fail(f"Linux must support symlink creation for this security test: {error}")
        pytest.skip(f"Symlink creation is unavailable: {error}")
    staging_parent = tmp_path / "staging-parent"
    staging_parent.mkdir()
    manager = WorkspaceManager(temp_root=staging_parent)

    with pytest.raises(WorkspaceError) as error:
        manager.prepare(source)

    expected = (
        WorkspaceErrorCode.PLATFORM_UNSUPPORTED
        if not sys.platform.startswith("linux")
        else WorkspaceErrorCode.UNSUPPORTED_ENTRY
    )
    assert error.value.code is expected
    assert secret.read_text(encoding="utf-8") == "synthetic secret"
    assert not list(staging_parent.iterdir())


def test_preparation_does_not_use_network_or_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    staging_parent = tmp_path / "staging-parent"
    staging_parent.mkdir()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Workspace preparation must remain local and non-executing.")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    manager = WorkspaceManager(temp_root=staging_parent)
    if not sys.platform.startswith("linux"):
        with pytest.raises(WorkspaceError) as error:
            manager.prepare(source)
        assert error.value.code is WorkspaceErrorCode.PLATFORM_UNSUPPORTED
    else:
        handle = manager.prepare(source)
        manager.cleanup(handle)
