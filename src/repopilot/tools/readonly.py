"""Strict argument contracts for the four read-only repository operations."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from repopilot.security.capabilities import Capability
from repopilot.tools.definition import ToolDefinition
from repopilot.tools.registry import ToolRegistry

_PathArgument = Annotated[str, Field(min_length=1, max_length=512)]


class _Arguments(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class DiscoverFilesArguments(_Arguments):
    """Bounded inventory of the authorized staged root."""

    directory: Literal["."] = Field(default=".", description="The fixed staged repository root.")
    suffixes: list[Annotated[str, Field(min_length=2, max_length=16)]] | None = Field(
        default=None, max_length=16
    )
    max_files: int = Field(default=100, ge=1, le=100)
    max_depth: int = Field(default=8, ge=0, le=8)
    max_entries: int = Field(default=5_000, ge=1, le=5_000)


class ReadTextArguments(_Arguments):
    """Read a bounded UTF-8 excerpt from one explicitly scoped file."""

    path: str = Field(min_length=1, max_length=512)
    start_line: int = Field(default=1, ge=1, le=1_000_000)
    end_line: int | None = Field(default=None, ge=2, le=1_000_001)
    max_bytes: int = Field(default=8_192, ge=1, le=8_192)
    max_lines: int = Field(default=100, ge=1, le=100)
    max_file_bytes: int = Field(default=1_000_000, ge=1, le=1_000_000)

    @model_validator(mode="after")
    def validate_line_range(self) -> ReadTextArguments:
        if self.end_line is not None and self.end_line <= self.start_line:
            raise ValueError("End line must be after start line.")
        return self


class SearchLiteralArguments(_Arguments):
    """Search a bounded explicit set of files for one literal query."""

    paths: list[_PathArgument] = Field(min_length=1, max_length=20)
    query: str = Field(min_length=1, max_length=256)
    case_sensitive: bool = True
    max_bytes: int = Field(default=256_000, ge=1, le=256_000)
    max_matches: int = Field(default=20, ge=1, le=20)


class IndexPythonArguments(_Arguments):
    """Index syntax from a bounded explicit set of Python files."""

    paths: list[_PathArgument] = Field(min_length=1, max_length=20)
    max_bytes: int = Field(default=2_000_000, ge=1, le=2_000_000)
    max_nodes: int = Field(default=20_000, ge=1, le=20_000)
    max_symbols: int = Field(default=100, ge=1, le=100)


def readonly_tool_definitions() -> tuple[ToolDefinition, ...]:
    """Create trusted, narrowly scoped definitions in stable registration order."""
    return (
        ToolDefinition(
            "repo_discover_files",
            "List eligible files below the fixed staged repository root.",
            DiscoverFilesArguments,
            capabilities=frozenset({Capability.REPOSITORY_READ}),
            resource_fields=("directory",),
            resource_type="directory",
        ),
        ToolDefinition(
            "repo_read_text",
            "Read a bounded UTF-8 excerpt from one eligible staged file.",
            ReadTextArguments,
            capabilities=frozenset({Capability.REPOSITORY_READ}),
            resource_fields=("path",),
        ),
        ToolDefinition(
            "repo_search_literal",
            "Search explicitly selected eligible staged files for a literal substring.",
            SearchLiteralArguments,
            capabilities=frozenset({Capability.REPOSITORY_SEARCH}),
            resource_fields=("paths",),
        ),
        ToolDefinition(
            "repo_index_python",
            "Return bounded syntactic symbols from explicitly selected Python files.",
            IndexPythonArguments,
            capabilities=frozenset({Capability.REPOSITORY_READ}),
            resource_fields=("paths",),
        ),
    )


def create_readonly_tool_registry() -> ToolRegistry:
    """Return an instance-local registry with only the four approved read tools."""
    return ToolRegistry(readonly_tool_definitions())
