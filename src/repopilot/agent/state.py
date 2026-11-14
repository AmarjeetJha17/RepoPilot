"""Finite run statuses shared by orchestration, reporting, and persistence."""

from enum import StrEnum


class RunStatus(StrEnum):
    """Lifecycle labels; transition rules belong to the future orchestrator."""

    CREATED = "CREATED"
    INSPECTING = "INSPECTING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
