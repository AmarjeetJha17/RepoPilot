"""Linux integration tests against manager-owned staged repository copies."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from repopilot.context import IntelligenceError, IntelligenceLimits, RepositoryIntelligence
from repopilot.sandbox.workspace import WorkspaceHandle, WorkspaceManager
from tests.fixtures.repository_intelligence import create_repository

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux workspace boundary."),
]


def _open_intelligence(
    tmp_path: Path, *, limits: IntelligenceLimits | None = None
) -> tuple[WorkspaceManager, WorkspaceHandle, Path, dict[str, bytes], RepositoryIntelligence]:
    source, files = create_repository(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    manager = WorkspaceManager(temp_root=staging)
    handle = manager.prepare(source)
    service = RepositoryIntelligence(manager, handle, limits=limits)
    return manager, handle, source, files, service


def test_discovery_is_sorted_filtered_and_reports_return_limit(tmp_path: Path) -> None:
    limits = IntelligenceLimits(max_files=2)
    manager, _handle, _source, _files, service = _open_intelligence(tmp_path, limits=limits)

    result = service.discover_files(suffixes={".PY"})

    assert [item.path for item in result.files] == ["notes/decoy.py", "notes/syntax.py"]
    assert result.truncated
    assert result.entries_scanned > len(result.files)
    manager.close()


def test_discovery_excludes_sensitive_and_binary_entries(tmp_path: Path) -> None:
    manager, _handle, _source, _files, service = _open_intelligence(tmp_path)

    discovered = {item.path for item in service.discover_files().files}

    assert ".env" not in discovered
    assert "local_credentials.txt" not in discovered
    assert "media/image.bin" not in discovered
    manager.close()


def test_reads_line_ranges_and_compares_staged_content_to_baseline(tmp_path: Path) -> None:
    manager, handle, source, files, service = _open_intelligence(tmp_path)
    original_hash = hashlib.sha256(files["notes/readme.txt"]).hexdigest()

    result = service.read_text("notes/readme.txt", start_line=2, end_line=4)

    assert result.text == "second needle\nthird line\n"
    assert (result.start_line, result.end_line_exclusive, result.total_lines) == (2, 4, 3)
    assert result.sha256 == original_hash
    assert result.baseline_matches
    (handle.staging_root / "notes/readme.txt").write_text("changed\n", encoding="utf-8")
    assert not service.read_text("notes/readme.txt").baseline_matches
    assert (source / "notes/readme.txt").read_bytes() == files["notes/readme.txt"]
    manager.close()


def test_reads_are_bounded_and_invalid_utf8_is_a_safe_error(tmp_path: Path) -> None:
    limits = IntelligenceLimits(max_file_bytes=512, max_read_bytes=8, max_read_lines=2)
    manager, _handle, _source, _files, service = _open_intelligence(tmp_path, limits=limits)

    bounded = service.read_text("notes/readme.txt")
    assert len(bounded.text.encode("utf-8")) <= 8
    assert bounded.truncated
    with pytest.raises(IntelligenceError) as invalid:
        service.read_text("notes/invalid.txt")
    assert getattr(invalid.value, "code", None).value == "invalid_encoding"
    manager.close()


def test_reads_reject_files_over_the_configured_input_bound(tmp_path: Path) -> None:
    manager, _handle, _source, _files, service = _open_intelligence(
        tmp_path, limits=IntelligenceLimits(max_file_bytes=64)
    )

    with pytest.raises(IntelligenceError) as oversized:
        service.read_text("notes/large.txt")

    assert oversized.value.code.value == "limit_exceeded"
    manager.close()


def test_literal_search_reports_stable_locations_and_match_truncation(tmp_path: Path) -> None:
    limits = IntelligenceLimits(max_matches=2)
    manager, _handle, _source, _files, service = _open_intelligence(tmp_path, limits=limits)

    result = service.search_literal("needle", suffixes={".txt"})

    assert [(item.path, item.line, item.column) for item in result.matches] == [
        ("notes/readme.txt", 1, 7),
        ("notes/readme.txt", 2, 8),
    ]
    assert result.truncated
    assert all(len(item.excerpt) <= limits.max_excerpt_chars for item in result.matches)
    manager.close()


def test_python_index_reports_symbols_and_syntax_errors_without_execution(tmp_path: Path) -> None:
    manager, _handle, source, _files, service = _open_intelligence(tmp_path)

    result = service.index_python()

    names = {(item.path, item.qualified_name, item.kind.value) for item in result.symbols}
    assert ("pkg/__init__.py", "Alpha.method.nested", "function") in names
    assert ("pkg/__init__.py", "async_task", "async_function") in names
    assert not any("Decoy" in item.qualified_name for item in result.symbols)
    assert any(issue.path == "notes/syntax.py" for issue in result.issues)
    assert not (source / "executed").exists()
    manager.close()


def test_context_selection_is_deterministic_and_bounded(tmp_path: Path) -> None:
    limits = IntelligenceLimits(max_context_bytes=50)
    manager, _handle, _source, _files, service = _open_intelligence(tmp_path, limits=limits)

    selected = service.select_context(("pkg/first.py", "notes/readme.txt", "pkg/first.py"))

    assert [item.path for item in selected.excerpts] == ["notes/readme.txt", "pkg/first.py"]
    assert selected.total_bytes <= limits.max_context_bytes
    assert selected.truncated
    assert all(item.sha256 for item in selected.excerpts)
    manager.close()
