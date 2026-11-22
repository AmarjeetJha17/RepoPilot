"""Provider-neutral staged patch models and safe result types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FileReplacement(BaseModel):
    """Complete replacement of one existing relative UTF-8 text file."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=512)
    operation: Literal["replace_text"]
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content: str = Field(max_length=1_000_000)


class PatchProposal(BaseModel):
    """Model-neutral patch proposal; it carries no authorization or filesystem root."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    replacements: tuple[FileReplacement, ...] = Field(min_length=1, max_length=20)


@dataclass(frozen=True, slots=True)
class PatchLimits:
    """Trusted application limits; proposal data cannot raise these bounds."""

    max_files: int = 20
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 4_000_000
    max_changed_lines: int = 20_000
    max_diff_bytes: int = 1_000_000
    max_diff_lines: int = 20_000

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 1 for value in self.as_tuple()):
            raise ValueError("Patch limits must be positive integers.")

    def as_tuple(self) -> tuple[int, ...]:
        return (
            self.max_files,
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_changed_lines,
            self.max_diff_bytes,
            self.max_diff_lines,
        )


class PatchFailure(StrEnum):
    """Safe failure categories; no filesystem paths or content are embedded."""

    INVALID_PROPOSAL = "invalid_proposal"
    LIMIT_EXCEEDED = "limit_exceeded"
    PATH_NOT_ELIGIBLE = "path_not_eligible"
    POLICY_DENIED = "policy_denied"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    SOURCE_CHANGED = "source_changed"
    STAGING_FAILED = "staging_failed"
    PARTIAL = "partial_failure"
    INVALID_TEXT = "invalid_text"


class PatchError(ValueError):
    """Safe patch-operation error with a stable category only."""

    def __init__(self, reason: PatchFailure) -> None:
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class PatchValidationResult:
    """Structural and workspace-baseline validation without side effects."""

    valid: bool
    reason: PatchFailure | None = None


@dataclass(frozen=True, slots=True)
class FileChangeSummary:
    """Path and content digests for a staged replacement, without source contents."""

    path: str
    before_sha256: str
    after_sha256: str


class PatchStagingStatus(StrEnum):
    """Outcome of single-file or best-effort multi-file staging."""

    STAGED = "staged"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class PatchStagingResult:
    """Reported staging outcome; multi-file application is not transactional."""

    status: PatchStagingStatus
    applied: tuple[FileChangeSummary, ...] = ()
    reason: PatchFailure | None = None


@dataclass(frozen=True, slots=True)
class PatchComparisonResult:
    """Comparison against trusted baseline metadata and retained baseline bytes."""

    changed_paths: tuple[str, ...]
    added_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiffPreview:
    """Sanitized bounded relative-path diff with explicit truncation metadata."""

    text: str
    truncated: bool
    total_bytes: int
    total_lines: int
