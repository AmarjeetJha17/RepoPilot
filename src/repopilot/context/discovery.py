"""Bounded deterministic enumeration of eligible staged files."""

from __future__ import annotations

from pathlib import PurePosixPath

from repopilot.context._support import safe_limit, translate_workspace_error
from repopilot.context.models import (
    DiscoveredFile,
    DiscoveryResult,
    IntelligenceLimits,
)
from repopilot.sandbox.read_access import WorkspaceReadAccess
from repopilot.sandbox.workspace import WorkspaceError


def discover_files(
    access: WorkspaceReadAccess,
    limits: IntelligenceLimits,
    *,
    suffixes: frozenset[str] | None = None,
    max_files: int | None = None,
    max_depth: int | None = None,
) -> DiscoveryResult:
    """Walk eligible staged entries in bounded order; report intentional cutoffs."""
    file_limit = safe_limit(max_files, limits.max_files)
    depth_limit = safe_limit(max_depth, limits.max_depth, allow_zero=True)
    collected: list[DiscoveredFile] = []
    scanned = 0
    truncated = False

    def walk(directory: str, depth: int) -> None:
        nonlocal scanned, truncated
        remaining = limits.max_entries - scanned
        if remaining <= 0:
            truncated = True
            return
        try:
            listing = access.list_directory(
                directory, max_entries=min(remaining, access.max_entries)
            )
        except WorkspaceError as error:
            raise translate_workspace_error(error) from error
        scanned += listing.entries_scanned
        for entry in listing.entries:
            path = f"{directory}/{entry.name}" if directory else entry.name
            if entry.is_directory:
                if depth >= depth_limit:
                    truncated = True
                else:
                    walk(path, depth + 1)
            elif suffixes is None or PurePosixPath(entry.name).suffix.casefold() in suffixes:
                collected.append(DiscoveredFile(path, entry.size_bytes))

    walk("", 0)
    collected.sort(key=lambda item: item.path)
    if len(collected) > file_limit:
        truncated = True
    return DiscoveryResult(tuple(collected[:file_limit]), scanned, truncated)
