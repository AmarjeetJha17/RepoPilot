"""Adversarial synthetic path cases for authorization scope enforcement."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import BaseModel

from repopilot.agent.contracts import ToolCall
from repopilot.security.capabilities import Capability
from repopilot.security.policy import (
    AuthorizationContext,
    DefaultPolicyEngine,
    ExecutionWorkspace,
    PolicyDecision,
    PolicyReasonCode,
)
from repopilot.tools import ToolDefinition, ToolRegistry
from repopilot.tools.registry import ValidatedToolCall

pytestmark = pytest.mark.security


class PathArguments(BaseModel):
    path: str


def _setup(root: Path, *, workspace: ExecutionWorkspace = ExecutionWorkspace.SOURCE):
    definition = ToolDefinition(
        "read-any-name",
        "Read one synthetic resource.",
        PathArguments,
        capabilities=frozenset({Capability.REPOSITORY_READ}),
        resource_fields=("path",),
    )
    engine = DefaultPolicyEngine(ToolRegistry((definition,)))
    context = AuthorizationContext(
        run_id="security-test",
        workspace_root=root,
        workspace=workspace,
        workspace_identity="synthetic-baseline",
        allowed_capabilities=frozenset({Capability.REPOSITORY_READ}),
    )
    return definition, engine, context


def _authorize(root: Path, path: str):
    definition, engine, context = _setup(root)
    (root / "inside.txt").write_text("synthetic", encoding="utf-8")
    call = ToolRegistry((definition,)).validate_call(
        ToolCall("call-1", definition.name, {"path": path})
    )
    return engine.authorize(call, context, root)


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "nested/../../outside.txt",
        "C:\\outside.txt",
        "C:outside.txt",
        "\\\\server\\share\\outside.txt",
        "\\\\?\\C:\\outside.txt",
        "\\\\.\\PhysicalDrive0",
        "/outside.txt",
        "inside.txt:secret-stream",
    ],
)
def test_rejects_traversal_and_platform_specific_absolute_paths(tmp_path: Path, path: str) -> None:
    result = _authorize(tmp_path, path)

    assert result.decision is PolicyDecision.DENY
    assert result.reason_code in {
        PolicyReasonCode.INVALID_RESOURCE_PATH,
        PolicyReasonCode.RESOURCE_OUTSIDE_WORKSPACE,
    }


def test_relative_backslash_path_is_normalized_within_root(tmp_path: Path) -> None:
    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "module.py").write_text("synthetic", encoding="utf-8")

    result = _authorize(tmp_path, r"src\module.py")

    assert result.decision is PolicyDecision.ALLOW


def test_resource_path_rejects_malformed_or_unresolvable_root(tmp_path: Path) -> None:
    from repopilot.security.paths import (
        PathAuthorizationError,
        PathFailure,
        authorize_resource_path,
    )

    with pytest.raises(PathAuthorizationError) as malformed:
        authorize_resource_path(
            tmp_path,
            object(),
            resource_type="file",
            sensitive_patterns=(),
            allow_missing=False,
            forbid_symlinks=False,
        )
    assert malformed.value.failure is PathFailure.INVALID

    with pytest.raises(PathAuthorizationError) as nul:
        authorize_resource_path(
            tmp_path,
            "bad\x00path",
            resource_type="file",
            sensitive_patterns=(),
            allow_missing=False,
            forbid_symlinks=False,
        )
    assert nul.value.failure is PathFailure.INVALID

    with (
        patch.object(Path, "resolve", side_effect=OSError("synthetic")),
        pytest.raises(PathAuthorizationError) as root_failure,
    ):
        authorize_resource_path(
            tmp_path,
            "inside.txt",
            resource_type="file",
            sensitive_patterns=(),
            allow_missing=False,
            forbid_symlinks=False,
        )
    assert root_failure.value.failure is PathFailure.OUTSIDE


def test_file_resource_cannot_resolve_to_workspace_directory(tmp_path: Path) -> None:
    result = _authorize(tmp_path, ".")

    assert result.reason_code is PolicyReasonCode.RESOURCE_TYPE_MISMATCH


def test_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("synthetic", encoding="utf-8")
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable in this environment: {error}")

    result = _authorize(root, "link/secret.txt")

    assert result.decision is PolicyDecision.DENY
    assert result.reason_code is PolicyReasonCode.RESOURCE_OUTSIDE_WORKSPACE


def test_staged_write_rejects_symlink_component(tmp_path: Path) -> None:
    from repopilot.security.paths import (
        PathAuthorizationError,
        PathFailure,
        authorize_resource_path,
    )

    target = tmp_path / "link" / "new.txt"
    with (
        patch.object(Path, "is_symlink", new=lambda path: path.name == "link"),
        pytest.raises(PathAuthorizationError) as caught,
    ):
        authorize_resource_path(
            tmp_path,
            "link/new.txt",
            resource_type="file",
            sensitive_patterns=(),
            allow_missing=True,
            forbid_symlinks=True,
        )

    assert caught.value.failure is PathFailure.SYMLINK
    assert not target.exists()


def test_staged_write_rejects_internal_symlink(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    target = root / "real.txt"
    target.write_text("synthetic", encoding="utf-8")
    try:
        (root / "alias.txt").symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable in this environment: {error}")

    definition = ToolDefinition(
        "write-by-any-name",
        "Write one synthetic resource.",
        PathArguments,
        capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
        resource_fields=("path",),
    )
    engine = DefaultPolicyEngine(ToolRegistry((definition,)))
    context = AuthorizationContext(
        run_id="security-test",
        workspace_root=root,
        workspace=ExecutionWorkspace.STAGING,
        workspace_identity="synthetic-staging",
        allowed_capabilities=frozenset({Capability.STAGED_FILE_MODIFICATION}),
    )
    call = ToolRegistry((definition,)).validate_call(
        ToolCall("call-1", definition.name, {"path": "alias.txt"})
    )

    result = engine.authorize(call, context, root)

    assert result.reason_code is PolicyReasonCode.SYMLINK_NOT_ALLOWED


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "nested/.env.local",
        ".ssh/id_rsa",
        ".aws/credentials",
        ".azure/accessTokens.json",
        ".config/gcloud/application_default_credentials.json",
        ".git/config",
        "server.pem",
        "id_ed25519",
    ],
)
def test_denies_default_sensitive_resource_patterns(tmp_path: Path, path: str) -> None:
    result = _authorize(tmp_path, path)

    assert result.decision is PolicyDecision.DENY
    assert result.reason_code is PolicyReasonCode.SENSITIVE_RESOURCE


def test_denies_run_specific_sensitive_patterns(tmp_path: Path) -> None:
    definition, engine, _ = _setup(tmp_path)
    context = AuthorizationContext(
        run_id="security-test",
        workspace_root=tmp_path,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity="synthetic-baseline",
        allowed_capabilities=frozenset({Capability.REPOSITORY_READ}),
        sensitive_resource_patterns=("private/**",),
    )
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "data.txt").write_text("synthetic", encoding="utf-8")
    call = ToolRegistry((definition,)).validate_call(
        ToolCall("call-1", definition.name, {"path": "private/data.txt"})
    )

    result = engine.authorize(call, context, tmp_path)

    assert result.reason_code is PolicyReasonCode.SENSITIVE_RESOURCE


def test_directory_capability_rejects_file_and_allows_directory(tmp_path: Path) -> None:
    definition = ToolDefinition(
        "search-any-name",
        "Search one synthetic directory.",
        PathArguments,
        capabilities=frozenset({Capability.REPOSITORY_SEARCH}),
        resource_fields=("path",),
        resource_type="directory",
    )
    engine = DefaultPolicyEngine(ToolRegistry((definition,)))
    context = AuthorizationContext(
        run_id="security-test",
        workspace_root=tmp_path,
        workspace=ExecutionWorkspace.SOURCE,
        workspace_identity="synthetic-baseline",
        allowed_capabilities=frozenset({Capability.REPOSITORY_SEARCH}),
    )
    (tmp_path / "file.txt").write_text("synthetic", encoding="utf-8")

    def call(path: str) -> ValidatedToolCall:
        return ToolRegistry((definition,)).validate_call(
            ToolCall("call-1", definition.name, {"path": path})
        )

    mismatch = engine.authorize(call("file.txt"), context, tmp_path)
    valid = engine.authorize(call("."), context, tmp_path)

    assert mismatch.reason_code is PolicyReasonCode.RESOURCE_TYPE_MISMATCH
    assert valid.decision is PolicyDecision.ALLOW
