"""Read-only, bounded repository discovery and context retrieval."""

from repopilot.context.intelligence import RepositoryIntelligence
from repopilot.context.models import (
    ContextExcerpt,
    ContextSelection,
    DiscoveredFile,
    DiscoveryResult,
    IntelligenceError,
    IntelligenceErrorCode,
    IntelligenceLimits,
    PythonSymbol,
    SearchMatch,
    SearchResult,
    SymbolIndexResult,
    SymbolIssue,
    SymbolKind,
    TextReadResult,
)

__all__ = [
    "ContextExcerpt",
    "ContextSelection",
    "DiscoveredFile",
    "DiscoveryResult",
    "IntelligenceError",
    "IntelligenceErrorCode",
    "IntelligenceLimits",
    "PythonSymbol",
    "RepositoryIntelligence",
    "SearchMatch",
    "SearchResult",
    "SymbolIndexResult",
    "SymbolIssue",
    "SymbolKind",
    "TextReadResult",
]
