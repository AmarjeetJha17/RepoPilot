"""Bounded literal search over eligible staged UTF-8 text files."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import PurePosixPath

from repopilot.context._support import relative_path, safe_limit, translate_workspace_error
from repopilot.context.discovery import discover_files
from repopilot.context.models import (
    DiscoveredFile,
    IntelligenceError,
    IntelligenceErrorCode,
    IntelligenceLimits,
    SearchMatch,
    SearchResult,
)
from repopilot.context.reader import decode_text
from repopilot.sandbox.read_access import WorkspaceReadAccess
from repopilot.sandbox.workspace import WorkspaceError


def search_literal(
    access: WorkspaceReadAccess,
    limits: IntelligenceLimits,
    query: str,
    *,
    suffixes: frozenset[str] | None = None,
    case_sensitive: bool = True,
    max_files: int | None = None,
    max_bytes: int | None = None,
    max_matches: int | None = None,
    paths: Sequence[str] | None = None,
) -> SearchResult:
    if (
        not isinstance(query, str)
        or not query
        or "\n" in query
        or "\r" in query
        or len(query) > limits.max_query_chars
    ):
        raise IntelligenceError(IntelligenceErrorCode.INVALID_QUERY)
    file_limit = safe_limit(max_files, limits.max_search_files)
    byte_limit = safe_limit(max_bytes, limits.max_search_bytes)
    match_limit = safe_limit(max_matches, limits.max_matches)
    if paths is None:
        inventory = discover_files(access, limits, suffixes=suffixes, max_files=file_limit)
        files = inventory.files
        truncated = inventory.truncated
    else:
        selected = sorted({relative_path(path) for path in paths})
        if suffixes is not None:
            selected = [
                path for path in selected if PurePosixPath(path).suffix.casefold() in suffixes
            ]
        truncated = len(selected) > file_limit
        files = tuple(DiscoveredFile(path, 0) for path in selected[:file_limit])
    matches: list[SearchMatch] = []
    files_scanned = bytes_scanned = files_skipped = 0
    stop = False
    pattern = re.compile(re.escape(query), 0 if case_sensitive else re.IGNORECASE)

    for item in files:
        remaining = byte_limit - bytes_scanned
        if remaining <= 0:
            truncated = True
            break
        files_scanned += 1
        try:
            raw = access.read_bytes(
                item.path,
                max_bytes=min(remaining, limits.max_file_bytes, access.max_file_bytes),
                allow_truncated=True,
            )
        except WorkspaceError as error:
            raise translate_workspace_error(error) from error
        bytes_scanned += len(raw.content)
        truncated |= raw.truncated
        try:
            text = decode_text(item.path, raw.content, partial=raw.truncated)
        except IntelligenceError:
            files_skipped += 1
            truncated = True
            if raw.truncated:
                break
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in pattern.finditer(line):
                if len(matches) >= match_limit:
                    truncated = True
                    stop = True
                    break
                excerpt = _excerpt(line, match.start(), limits.max_excerpt_chars)
                matches.append(SearchMatch(item.path, line_number, match.start() + 1, excerpt))
            if stop:
                break
        if stop or raw.truncated:
            break

    return SearchResult(tuple(matches), files_scanned, bytes_scanned, files_skipped, truncated)


def _excerpt(line: str, match_start: int, max_chars: int) -> str:
    if len(line) <= max_chars:
        return line
    start = max(0, min(match_start - max_chars // 2, len(line) - max_chars))
    return line[start : start + max_chars]
