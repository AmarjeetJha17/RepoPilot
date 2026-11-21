"""Typed, content-minimized results for read-only repository intelligence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class IntelligenceErrorCode(StrEnum):
    """Stable failure categories that never include host paths or file contents."""

    INVALID_PATH = "invalid_path"
    INVALID_QUERY = "invalid_query"
    INVALID_RANGE = "invalid_range"
    WORKSPACE_UNAVAILABLE = "workspace_unavailable"
    UNSUPPORTED_ENTRY = "unsupported_entry"
    LIMIT_EXCEEDED = "limit_exceeded"
    INVALID_ENCODING = "invalid_encoding"
    NOT_TEXT = "not_text"
    SYNTAX_ERROR = "syntax_error"
    AST_LIMIT_EXCEEDED = "ast_limit_exceeded"


class IntelligenceError(ValueError):
    """A safe repository-intelligence failure with a stable code."""

    def __init__(self, code: IntelligenceErrorCode) -> None:
        self.code = code
        super().__init__(f"Repository intelligence operation failed: {code.value}.")


@dataclass(frozen=True, slots=True)
class IntelligenceLimits:
    """Hard per-service bounds for traversal, reads, search, AST parsing and context."""

    max_entries: int = 20_000
    max_files: int = 2_000
    max_depth: int = 20
    max_file_bytes: int = 1_000_000
    max_read_bytes: int = 64_000
    max_read_lines: int = 400
    max_search_files: int = 500
    max_search_bytes: int = 4_000_000
    max_query_chars: int = 1_024
    max_matches: int = 500
    max_excerpt_chars: int = 240
    max_ast_files: int = 500
    max_ast_bytes: int = 8_000_000
    max_ast_nodes: int = 50_000
    max_context_bytes: int = 64_000

    def __post_init__(self) -> None:
        values = tuple((field, getattr(self, field)) for field in self.__dataclass_fields__)
        if any(type(value) is not int or value < 0 for _, value in values):
            raise ValueError("Intelligence limits must be non-negative integers.")
        if any(value == 0 for field, value in values if field != "max_depth"):
            raise ValueError("Intelligence limits must be positive except max_depth.")


@dataclass(frozen=True, slots=True)
class DiscoveredFile:
    """One eligible file, identified only by its staging-root-relative path."""

    path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Deterministic inventory with explicit result/depth truncation information."""

    files: tuple[DiscoveredFile, ...]
    entries_scanned: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class TextReadResult:
    """UTF-8 excerpt, one-based inclusive start and exclusive end line numbers."""

    path: str
    text: str
    start_line: int
    end_line_exclusive: int
    total_lines: int
    sha256: str
    baseline_matches: bool
    truncated: bool


@dataclass(frozen=True, slots=True)
class SearchMatch:
    """One literal match with a one-based line/column and bounded line excerpt."""

    path: str
    line: int
    column: int
    excerpt: str


@dataclass(frozen=True, slots=True)
class SearchResult:
    """Stable search results; truncated means some eligible input may remain unseen."""

    matches: tuple[SearchMatch, ...]
    files_scanned: int
    bytes_scanned: int
    files_skipped: int
    truncated: bool


class SymbolKind(StrEnum):
    """Syntactic Python definition categories; not semantic or runtime resolution."""

    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    CLASS = "class"
    METHOD = "method"
    ASYNC_METHOD = "async_method"


@dataclass(frozen=True, slots=True)
class PythonSymbol:
    """One AST definition; start line includes decorators when present."""

    path: str
    name: str
    qualified_name: str
    kind: SymbolKind
    start_line: int
    end_line: int | None


@dataclass(frozen=True, slots=True)
class SymbolIssue:
    """Safe per-file parse issue with no source text or exception details."""

    path: str
    code: IntelligenceErrorCode


@dataclass(frozen=True, slots=True)
class SymbolIndexResult:
    """Deterministic syntactic index with explicit file/byte truncation."""

    symbols: tuple[PythonSymbol, ...]
    issues: tuple[SymbolIssue, ...]
    files_scanned: int
    bytes_scanned: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class ContextExcerpt:
    """Selected excerpt and digest of returned text, not the full source file."""

    path: str
    text: str
    start_line: int
    end_line_exclusive: int
    sha256: str
    baseline_matches: bool
    truncated: bool


@dataclass(frozen=True, slots=True)
class ContextSelection:
    """Deterministic path-selected excerpts under a total returned-byte budget."""

    excerpts: tuple[ContextExcerpt, ...]
    total_bytes: int
    truncated: bool
