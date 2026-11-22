"""Linux security boundary tests for staged patch authorization and path handling."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from repopilot.application.patch_staging import PatchStager
from repopilot.sandbox.patches import FileReplacement, PatchFailure, PatchProposal
from repopilot.sandbox.workspace import (
    WorkspaceError,
    WorkspaceManager,
    workspace_identity_for_handle,
)
from repopilot.security.capabilities import Capability
from repopilot.security.policy import AuthorizationContext, ExecutionWorkspace

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="Secure patch staging is Linux-only."
    ),
]


def test_symlink_and_outside_paths_are_rejected_without_touching_target(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "inside.py").write_text("before\n", encoding="utf-8")
    (tmp_path / "staging").mkdir()
    manager = WorkspaceManager(temp_root=tmp_path / "staging")
    handle = manager.prepare(source)
    outside = tmp_path / "outside.py"
    outside.write_text("outside\n", encoding="utf-8")
    linked = handle.staging_root / "link.py"
    linked.symlink_to(outside)
    context = AuthorizationContext(
        run_id="security-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )
    stager = PatchStager(manager, handle, context)
    proposal = PatchProposal(
        replacements=(
            FileReplacement(
                path="link.py",
                operation="replace_text",
                expected_sha256=hashlib.sha256(b"outside\n").hexdigest(),
                content="changed\n",
            ),
        )
    )

    result = stager.stage(proposal)

    assert result.reason is PatchFailure.PATH_NOT_ELIGIBLE
    assert str(tmp_path) not in str(result)
    assert outside.read_text(encoding="utf-8") == "outside\n"
    manager.cleanup(handle)


def test_workspace_binding_mismatch_is_rejected_before_staging(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("before\n", encoding="utf-8")
    (tmp_path / "staging").mkdir()
    manager = WorkspaceManager(temp_root=tmp_path / "staging")
    handle = manager.prepare(source)
    context = AuthorizationContext(
        run_id="security-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity="workspace:wrong",
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )

    with pytest.raises(ValueError):
        PatchStager(manager, handle, context)
    assert (handle.staging_root / "module.py").read_text(encoding="utf-8") == "before\n"
    manager.cleanup(handle)


def test_parent_traversal_is_denied_without_disclosing_or_touching_outside_file(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("before\n", encoding="utf-8")
    (tmp_path / "staging").mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("outside\n", encoding="utf-8")
    manager = WorkspaceManager(temp_root=tmp_path / "staging")
    handle = manager.prepare(source)
    context = AuthorizationContext(
        run_id="security-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )
    stager = PatchStager(manager, handle, context)
    proposal = PatchProposal(
        replacements=(
            FileReplacement(
                path="../outside.py",
                operation="replace_text",
                expected_sha256=hashlib.sha256(b"outside\n").hexdigest(),
                content="changed\n",
            ),
        )
    )

    result = stager.stage(proposal)

    assert result.reason is PatchFailure.PATH_NOT_ELIGIBLE
    assert str(tmp_path) not in str(result)
    assert outside.read_text(encoding="utf-8") == "outside\n"
    manager.cleanup(handle)


def test_copied_handle_and_foreign_manager_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("before\n", encoding="utf-8")
    first_parent = tmp_path / "first-staging"
    second_parent = tmp_path / "second-staging"
    first_parent.mkdir()
    second_parent.mkdir()
    manager = WorkspaceManager(temp_root=first_parent)
    foreign_manager = WorkspaceManager(temp_root=second_parent)
    handle = manager.prepare(source)
    context = AuthorizationContext(
        run_id="security-run",
        workspace_root=handle.staging_root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity=workspace_identity_for_handle(handle),
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )

    with pytest.raises(WorkspaceError):
        PatchStager(manager, replace(handle), context)
    with pytest.raises(WorkspaceError):
        PatchStager(foreign_manager, handle, context)
    assert (handle.staging_root / "module.py").read_text(encoding="utf-8") == "before\n"
    manager.cleanup(handle)
    foreign_manager.close()
