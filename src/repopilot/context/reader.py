"""Strict UTF-8 reads and deterministic line excerpts from staged files."""

from __future__ import annotations

import hashlib

from repopilot.context._support import relative_path, safe_limit, translate_workspace_error
from repopilot.context.models import (
    IntelligenceError,
    IntelligenceErrorCode,
    IntelligenceLimits,
    TextReadResult,
)
from repopilot.sandbox.read_access import WorkspaceReadAccess
from repopilot.sandbox.workspace import WorkspaceError

_BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".bin",
        ".dll",
        ".docx",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".mp3",
        ".mp4",
        ".pdf",
        ".png",
        ".pyc",
        ".so",
        ".tar",
        ".whl",
        ".xlsx",
        ".zip",
    }
)


def read_full_text(
    access: WorkspaceReadAccess,
    path: str,
    *,
    max_bytes: int,
) -> tuple[str, bytes]:
    """Read one complete eligible text file for internal search and AST operations."""
    safe_path = relative_path(path)
    try:
        content = access.read_bytes(safe_path, max_bytes=max_bytes)
    except WorkspaceError as error:
        raise translate_workspace_error(error) from error
    text = decode_text(safe_path, content.content)
    return text, content.content


def decode_text(path: str, content: bytes, *, partial: bool = False) -> str:
    if "." in path.rsplit("/", 1)[-1] and path.rsplit(".", 1)[-1].casefold() in {
        suffix.removeprefix(".") for suffix in _BINARY_SUFFIXES
    }:
        raise IntelligenceError(IntelligenceErrorCode.NOT_TEXT)
    if b"\x00" in content:
        raise IntelligenceError(IntelligenceErrorCode.NOT_TEXT)
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        if partial and error.end == len(content):
            return content.decode("utf-8", errors="ignore")
        raise IntelligenceError(IntelligenceErrorCode.INVALID_ENCODING) from error


def read_text(
    access: WorkspaceReadAccess,
    baseline: dict[str, str],
    limits: IntelligenceLimits,
    path: str,
    *,
    start_line: int = 1,
    end_line: int | None = None,
    max_bytes: int | None = None,
    max_lines: int | None = None,
) -> TextReadResult:
    safe_path = relative_path(path)
    if type(start_line) is not int or start_line < 1:
        raise IntelligenceError(IntelligenceErrorCode.INVALID_RANGE)
    if end_line is not None and (type(end_line) is not int or end_line <= start_line):
        raise IntelligenceError(IntelligenceErrorCode.INVALID_RANGE)
    byte_limit = safe_limit(max_bytes, limits.max_read_bytes)
    line_limit = safe_limit(max_lines, limits.max_read_lines)
    text, content = read_full_text(
        access,
        safe_path,
        max_bytes=min(limits.max_file_bytes, access.max_file_bytes),
    )
    lines = text.splitlines(keepends=True)
    requested_end = len(lines) + 1 if end_line is None else min(end_line, len(lines) + 1)
    requested_lines = lines[start_line - 1 : requested_end - 1]
    truncated = len(requested_lines) > line_limit
    selected = requested_lines[:line_limit]
    result_lines: list[str] = []
    returned_bytes = 0
    for line in selected:
        encoded = line.encode("utf-8")
        remaining = byte_limit - returned_bytes
        if len(encoded) > remaining:
            if remaining > 0:
                result_lines.append(encoded[:remaining].decode("utf-8", errors="ignore"))
            truncated = True
            break
        result_lines.append(line)
        returned_bytes += len(encoded)
    excerpt = "".join(result_lines)
    digest = hashlib.sha256(content).hexdigest()
    return TextReadResult(
        safe_path,
        excerpt,
        start_line,
        start_line + len(result_lines),
        len(lines),
        digest,
        baseline.get(safe_path) == digest,
        truncated,
    )
