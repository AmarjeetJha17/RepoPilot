"""Portable tests for pure coding-task demonstration contracts."""

from __future__ import annotations

import hashlib
from pathlib import Path

from repopilot.application.coding_task_demo import (
    _BASELINE_SHA256,
    _BASELINE_SOURCE,
    CodingTaskDemoReport,
    _create_fixture,
    _source_is_unchanged,
)


def test_baseline_fixture_digest_matches_its_exact_utf8_bytes() -> None:
    digest = hashlib.sha256(_BASELINE_SOURCE.encode("utf-8")).hexdigest()

    assert digest == _BASELINE_SHA256


def test_report_json_is_stable_and_does_not_add_machine_paths() -> None:
    report = CodingTaskDemoReport(diff="--- a/src/first_item.py\n+++ b/src/first_item.py")

    first = report.to_json()

    assert report.to_json() == first
    assert str(Path.home()) not in first
    assert "synthetic_repository_id" in first
    assert '"independent_verification":false' in first


def test_source_snapshot_detects_file_changes_and_unexpected_files(tmp_path: Path) -> None:
    fixture_files = _create_fixture(tmp_path)
    source_before = {tmp_path / relative: content for relative, content in fixture_files.items()}

    assert _source_is_unchanged(tmp_path, source_before)

    (tmp_path / "src" / "first_item.py").write_bytes(b"changed")
    assert not _source_is_unchanged(tmp_path, source_before)

    (tmp_path / "src" / "first_item.py").write_bytes(fixture_files["src/first_item.py"])
    (tmp_path / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    assert not _source_is_unchanged(tmp_path, source_before)
