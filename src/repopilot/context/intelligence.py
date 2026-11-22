"""Application-facing, read-only repository intelligence service."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from repopilot.context._support import (
    relative_path,
    safe_limit,
    suffix_filter,
    translate_workspace_error,
)
from repopilot.context.discovery import discover_files as _discover_files
from repopilot.context.models import (
    ContextExcerpt,
    ContextSelection,
    DiscoveredFile,
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
        self._manager = manager
        self._handle = handle

    def is_bound_to(self, manager: WorkspaceManager, handle: WorkspaceHandle) -> bool:
        """Check object-identity binding; the manager still revalidates active ownership."""
        return (
            self._manager is manager
            and self._handle is handle
            and self._access.is_bound_to(manager, handle)
        )

    def discover_files(
        self,
        *,
        suffixes: Iterable[str] | None = None,
        max_files: int | None = None,
        max_depth: int | None = None,
        max_entries: int | None = None,
    ) -> DiscoveryResult:
        normalized = suffix_filter(suffixes)
        return _discover_files(
            self._access,
            self.limits,
            suffixes=normalized,
            max_files=max_files,
            max_depth=max_depth,
            max_entries=max_entries,
        )

    def read_text(
        self,
        path: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        max_bytes: int | None = None,
        max_lines: int | None = None,
        max_file_bytes: int | None = None,
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
            max_file_bytes=max_file_bytes,
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
        paths: Sequence[str] | None = None,
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
            paths=paths,
        )

    def index_python(
        self,
        paths: Sequence[str] | None = None,
        *,
        max_files: int | None = None,
        max_bytes: int | None = None,
        max_nodes: int | None = None,
        max_symbols: int | None = None,
    ) -> SymbolIndexResult:
        file_limit = safe_limit(max_files, self.limits.max_ast_files)
        byte_limit = safe_limit(max_bytes, self.limits.max_ast_bytes)
        node_limit = safe_limit(max_nodes, self.limits.max_ast_nodes)
        symbol_limit = safe_limit(max_symbols, self.limits.max_ast_nodes)
        if paths is None:
            inventory = self.discover_files(suffixes={".py"}, max_files=file_limit)
            files = inventory.files
            truncated = inventory.truncated
        else:
            selected = sorted({relative_path(path) for path in paths})
            if any(not path.casefold().endswith(".py") for path in selected):
                raise IntelligenceError(IntelligenceErrorCode.INVALID_PATH)
            truncated = len(selected) > file_limit
            files = tuple(DiscoveredFile(path, 0) for path in selected[:file_limit])
        symbols: list[PythonSymbol] = []
        issues: list[SymbolIssue] = []
        files_scanned = bytes_scanned = 0
        for item in files:
            files_scanned += 1
            remaining = byte_limit - bytes_scanned
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
                symbols.extend(extract_symbols(item.path, source, max_nodes=node_limit))
                if len(symbols) > symbol_limit:
                    del symbols[symbol_limit:]
                    truncated = True
                    break
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
