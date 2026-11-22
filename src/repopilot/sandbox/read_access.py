"""No-follow, manager-validated read access without exposing file descriptors."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

from repopilot.sandbox.workspace import (
    WorkspaceCleanupState,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceHandle,
    WorkspaceManager,
    _directory_flags,
    _is_excluded,
    _is_reparse,
    _mount_points_under,
    _OwnedWorkspace,
    _read_mount_points,
    _root_name_matches,
    _same_identity,
    _same_stat,
    _validate_component,
)

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True, slots=True)
class WorkspaceEntry:
    """Safe metadata for an eligible direct child of an active staged directory."""

    name: str
    is_directory: bool
    size_bytes: int


@dataclass(frozen=True, slots=True)
class WorkspaceDirectoryListing:
    """Eligible metadata and raw entry count for a bounded direct-directory scan."""

    entries: tuple[WorkspaceEntry, ...]
    entries_scanned: int


@dataclass(frozen=True, slots=True)
class WorkspaceBytes:
    """Bounded file bytes and whether the result stopped at its requested byte cap."""

    content: bytes
    size_bytes: int
    truncated: bool


class WorkspaceReadAccess:
    """Manager-issued capability exposing only bounded relative listing and byte reads."""

    def __init__(self, manager: WorkspaceManager, handle: WorkspaceHandle) -> None:
        self._manager = manager
        self._handle = handle

    @property
    def max_entries(self) -> int:
        return self._manager._limits.max_files

    @property
    def max_file_bytes(self) -> int:
        return self._manager._limits.max_file_bytes

    def is_bound_to(self, manager: WorkspaceManager, handle: WorkspaceHandle) -> bool:
        """Return whether this view belongs to the exact manager and handle objects."""
        return self._manager is manager and self._handle is handle

    def list_directory(
        self, relative_path: str = "", *, max_entries: int
    ) -> WorkspaceDirectoryListing:
        """List eligible direct children; reject a directory that exceeds its bound."""
        if (
            type(max_entries) is not int
            or max_entries <= 0
            or max_entries > self._manager._limits.max_files
        ):
            raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
        owned = self._active_owned()
        parts = _relative_parts(relative_path, allow_empty=True)
        directory_fd = self._open_directory(owned.root_fd, parts)
        try:
            names: list[str] = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if len(names) >= max_entries:
                        raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
                    names.append(entry.name)
            names.sort(key=lambda name: (name.casefold(), name))
            root_device = os.fstat(owned.root_fd).st_dev
            parent = "/".join(parts)
            seen: set[str] = set()
            result: list[WorkspaceEntry] = []
            for name in names:
                relative = f"{parent}/{name}" if parent else name
                _validate_component(name, seen, relative)
                if _is_excluded(relative):
                    continue
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _is_reparse(info.st_mode, info):
                    continue
                if info.st_dev != root_device:
                    raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
                if stat.S_ISDIR(info.st_mode):
                    result.append(WorkspaceEntry(name, True, 0))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    result.append(WorkspaceEntry(name, False, info.st_size))
            self._active_owned()
            return WorkspaceDirectoryListing(tuple(result), len(names))
        except WorkspaceError:
            raise
        except OSError as error:
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY) from error
        finally:
            os.close(directory_fd)

    def read_bytes(
        self,
        relative_path: str,
        *,
        max_bytes: int,
        allow_truncated: bool = False,
    ) -> WorkspaceBytes:
        """Read one eligible regular file, revalidating each component without following links."""
        if (
            type(max_bytes) is not int
            or max_bytes <= 0
            or max_bytes > self._manager._limits.max_file_bytes
        ):
            raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
        owned = self._active_owned()
        parts = _relative_parts(relative_path, allow_empty=False)
        _validate_component(parts[-1], set(), relative_path)
        if _is_excluded(relative_path):
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
        parent_fd = self._open_directory(owned.root_fd, parts[:-1])
        descriptor = -1
        try:
            name = parts[-1]
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            device = os.fstat(owned.root_fd).st_dev
            if (
                not stat.S_ISREG(info.st_mode)
                or _is_reparse(info.st_mode, info)
                or info.st_dev != device
                or info.st_nlink != 1
            ):
                raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
            if info.st_size > max_bytes and not allow_truncated:
                raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
            descriptor = os.open(
                name,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_identity(info, opened):
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            if opened.st_dev != device or opened.st_nlink != 1:
                raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)

            content = bytearray()
            truncated = opened.st_size > max_bytes
            read_limit = max_bytes if truncated else max_bytes + 1
            while len(content) < read_limit:
                chunk = os.read(descriptor, min(64 * 1024, read_limit - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) > max_bytes:
                truncated = True
                if not allow_truncated:
                    raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
                del content[max_bytes:]
            if not _same_stat(opened, os.fstat(descriptor)):
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            if not truncated and len(content) != opened.st_size:
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            self._active_owned()
            return WorkspaceBytes(bytes(content), opened.st_size, truncated)
        except WorkspaceError:
            raise
        except OSError as error:
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)

    def _active_owned(self) -> _OwnedWorkspace:
        try:
            owned = self._manager._owned(self._handle)
        except WorkspaceError:
            raise
        if owned.cleanup_state is not WorkspaceCleanupState.ACTIVE or not _root_name_matches(owned):
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        if _mount_points_under(self._handle.staging_root, _read_mount_points()):
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
        return owned

    def _open_directory(self, root_fd: int, parts: tuple[str, ...]) -> int:
        descriptor = os.dup(root_fd)
        device = os.fstat(root_fd).st_dev
        prefix: list[str] = []
        seen: set[str] = set()
        try:
            for name in parts:
                prefix.append(name)
                relative = "/".join(prefix)
                _validate_component(name, seen, relative)
                if _is_excluded(relative):
                    raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or _is_reparse(info.st_mode, info)
                    or info.st_dev != device
                ):
                    raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
                child_fd = os.open(name, _directory_flags(), dir_fd=descriptor)
                if not _same_identity(info, os.fstat(child_fd)):
                    os.close(child_fd)
                    raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
                os.close(descriptor)
                descriptor = child_fd
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise


def _relative_parts(value: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, str) or "\x00" in value or "\\" in value or ":" in value:
        raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
    windows_path = PureWindowsPath(value)
    posix_path = PurePosixPath(value)
    if windows_path.drive or windows_path.is_absolute() or posix_path.is_absolute():
        raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
    if value == "" and allow_empty:
        return ()
    parts = tuple(value.split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
    return parts
