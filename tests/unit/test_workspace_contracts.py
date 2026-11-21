"""Immutable value contracts for repository workspace staging."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from repopilot.sandbox.workspace import (
    BaselineFile,
    BaselineManifest,
    WorkspaceLimits,
    WorkspacePreparationStatus,
    _contains_known_secret,
    _mount_points_under,
)

pytestmark = pytest.mark.unit


def test_manifest_serialization_is_stable_and_contains_only_relative_metadata() -> None:
    manifest = BaselineManifest(
        1,
        (BaselineFile("src/module.py", 3, "a" * 64),),
        3,
    )

    assert manifest.to_json() == (
        '{"files":[{"path":"src/module.py","sha256":"'
        + "a" * 64
        + '","size_bytes":3}],"format_version":1,"total_bytes":3,"total_files":1}'
    )
    assert ":\\" not in manifest.to_json()
    assert WorkspacePreparationStatus.PREPARED.value == "prepared"
    with pytest.raises(FrozenInstanceError):
        manifest.total_bytes = 4  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_bytes": -1},
        {"max_total_bytes": -1},
        {"max_files": 0},
        {"max_depth": -1},
        {"max_files": True},
    ],
)
def test_workspace_limits_reject_invalid_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        WorkspaceLimits(**kwargs)  # type: ignore[arg-type]


def test_mount_detection_only_rejects_descendant_mounts() -> None:
    source = Path("/tmp/synthetic-repository")

    mounts = _mount_points_under(
        source,
        (
            Path("/"),
            Path("/tmp"),
            source,
            source / "mounted-child",
        ),
    )

    assert mounts == (source / "mounted-child",)


@pytest.mark.parametrize(
    "content",
    [
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"AWS key AKIA1234567890ABCDEF",
        b'api_key = "synthetic-value-123456789"',
        b"Authorization: Bearer synthetic-token-value-123456789",
    ],
)
def test_common_embedded_secret_patterns_are_detected(content: bytes) -> None:
    assert _contains_known_secret(content)


def test_ordinary_source_is_not_matched_as_a_secret() -> None:
    assert not _contains_known_secret(b"VALUE = 1\n")
