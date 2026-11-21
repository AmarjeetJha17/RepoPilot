"""Application-facing, read-only repository intelligence service."""

from __future__ import annotations

from collections.abc import Iterable

from repopilot.context._support import relative_path, suffix_filter, translate_workspace_error
from repopilot.context.discovery import discover_files as _discover_files
from repopilot.context.models import (
    ContextExcerpt,
    ContextSelection,
    DiscoveryResult,
    IntelligenceError,
    IntelligenceErrorCode,
    IntelligenceLimits,
    PythonSymbol,
    SearchResult,
    SymbolIndexResult,
    SymbolIssue,
    TextReadResult,
)
from repopilot.context.reader import read_full_text
from repopilot.context.reader import read_text as _read_text
from repopilot.context.search import search_literal as _search_literal
from repopilot.context.symbols import extract_symbols
from repopilot.sandbox.workspace import WorkspaceError, WorkspaceHandle, WorkspaceManager


class RepositoryIntelligence:
    """Read-only queries over the active staged copy owned by a WorkspaceManager."""

    def __init__(
        self,
        manager: WorkspaceManager,
        handle: WorkspaceHandle,
        *,
        limits: IntelligenceLimits | None = None,
    ) -> None:
        self.limits = limits or IntelligenceLimits()
        try:
            self._access = manager.read_access(handle)
        except WorkspaceError as error:
            raise translate_workspace_error(error) from error
        self._baseline = {item.path: item.sha256 for item in handle.baseline.files}

    def discover_files(
        self,
        *,
        suffixes: Iterable[str] | None = None,
        max_files: int | None = None,
        max_depth: int | None = None,
    ) -> DiscoveryResult:
        normalized = suffix_filter(suffixes)
        return _discover_files(
            self._access,
            self.limits,
            suffixes=normalized,
            max_files=max_files,
            max_depth=max_depth,
        )

    def read_text(
        self,
        path: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        max_bytes: int | None = None,
        max_lines: int | None = None,
    ) -> TextReadResult:
        return _read_text(
            self._access,
            self._baseline,
            self.limits,
            path,
            start_line=start_line,
            end_line=end_line,
            max_bytes=max_bytes,
            max_lines=max_lines,
        )

    def search_literal(
        self,
        query: str,
        *,
        suffixes: Iterable[str] | None = None,
        case_sensitive: bool = True,
        max_files: int | None = None,
        max_bytes: int | None = None,
        max_matches: int | None = None,
    ) -> SearchResult:
        normalized = suffix_filter(suffixes)
        return _search_literal(
            self._access,
            self.limits,
            query,
            suffixes=normalized,
            case_sensitive=case_sensitive,
            max_files=max_files,
            max_bytes=max_bytes,
            max_matches=max_matches,
        )

    def index_python(self) -> SymbolIndexResult:
        inventory = self.discover_files(suffixes={".py"}, max_files=self.limits.max_ast_files)
        symbols: list[PythonSymbol] = []
        issues: list[SymbolIssue] = []
        files_scanned = bytes_scanned = 0
        truncated = inventory.truncated
        for item in inventory.files:
            files_scanned += 1
            remaining = self.limits.max_ast_bytes - bytes_scanned
            if remaining <= 0:
                truncated = True
                break
            files_limit = min(remaining, self.limits.max_file_bytes, self._access.max_file_bytes)
            if item.size_bytes > files_limit:
                issues.append(SymbolIssue(item.path, IntelligenceErrorCode.LIMIT_EXCEEDED))
                truncated = True
                continue
            try:
                source, content = read_full_text(self._access, item.path, max_bytes=files_limit)
                bytes_scanned += len(content)
                symbols.extend(
                    extract_symbols(item.path, source, max_nodes=self.limits.max_ast_nodes)
                )
            except IntelligenceError as error:
                issues.append(SymbolIssue(item.path, error.code))
                truncated |= error.code is IntelligenceErrorCode.AST_LIMIT_EXCEEDED
        return SymbolIndexResult(
            tuple(
                sorted(symbols, key=lambda item: (item.path, item.start_line, item.qualified_name))
            ),
            tuple(issues),
            files_scanned,
            bytes_scanned,
            truncated,
        )

    def select_context(self, paths: Iterable[str]) -> ContextSelection:
        selected_paths = sorted({relative_path(path) for path in paths})
        excerpts: list[ContextExcerpt] = []
        total_bytes = 0
        truncated = False
        for path in selected_paths:
            remaining = self.limits.max_context_bytes - total_bytes
            if remaining <= 0:
                truncated = True
                break
            try:
                result = self.read_text(path, max_bytes=min(remaining, self.limits.max_read_bytes))
            except IntelligenceError as error:
                if error.code is IntelligenceErrorCode.LIMIT_EXCEEDED:
                    truncated = True
                    continue
                raise
            size = len(result.text.encode("utf-8"))
            total_bytes += size
            truncated |= result.truncated
            excerpts.append(
                ContextExcerpt(
                    result.path,
                    result.text,
                    result.start_line,
                    result.end_line_exclusive,
                    result.sha256,
                    result.baseline_matches,
                    result.truncated,
                )
            )
        return ContextSelection(tuple(excerpts), total_bytes, truncated)
