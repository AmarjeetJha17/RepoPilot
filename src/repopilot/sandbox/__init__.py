"""Isolated workspace preparation and execution environment interfaces."""

from repopilot.sandbox.workspace import (
    BaselineFile,
    BaselineManifest,
    IntegrityChange,
    IntegrityChangeKind,
    IntegrityReport,
    WorkspaceCleanupState,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceHandle,
    WorkspaceIdentity,
    WorkspaceLimits,
    WorkspaceManager,
    WorkspacePreparationStatus,
)

__all__ = [
    "BaselineFile",
    "BaselineManifest",
    "IntegrityChange",
    "IntegrityChangeKind",
    "IntegrityReport",
    "WorkspaceCleanupState",
    "WorkspaceError",
    "WorkspaceErrorCode",
    "WorkspaceHandle",
    "WorkspaceIdentity",
    "WorkspaceLimits",
    "WorkspaceManager",
    "WorkspacePreparationStatus",
]
