"""Manager-bound, descriptor-relative replacement of one staged regular file."""

from __future__ import annotations

import hashlib
import os
import stat
from secrets import token_hex

from repopilot.sandbox.read_access import WorkspaceReadAccess, _relative_parts
from repopilot.sandbox.workspace import (
    _CLOEXEC,
    _NOFOLLOW,
    IntegrityChangeKind,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceHandle,
    WorkspaceManager,
    _is_excluded,
    _is_reparse,
    _same_identity,
    _same_stat,
    _validate_component,
    _write_all,
)


class WorkspaceWriteAccess:
    """Trusted write capability that only replaces existing files in its owned staging root."""

    def __init__(self, manager: WorkspaceManager, handle: WorkspaceHandle) -> None:
        self._manager = manager
        self._handle = handle

    def is_bound_to(self, manager: WorkspaceManager, handle: WorkspaceHandle) -> bool:
        return self._manager is manager and self._handle is handle

    def replace_bytes(
        self,
        relative_path: str,
        *,
        expected_sha256: str,
        content: bytes,
        max_original_bytes: int,
        max_replacement_bytes: int,
    ) -> str:
        """Atomically replace one bounded staged file if its current content hash matches."""
        if (
            type(max_original_bytes) is not int
            or not 1 <= max_original_bytes <= self._manager._limits.max_file_bytes
            or type(max_replacement_bytes) is not int
            or not 1 <= max_replacement_bytes <= self._manager._limits.max_file_bytes
            or not isinstance(content, bytes)
            or len(content) > max_replacement_bytes
            or not _is_sha256(expected_sha256)
            or b"\x00" in content
        ):
            raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)

        replacement_completed = False
        try:
            reader = self._manager.read_access(self._handle)
            owned = reader._active_owned()
            parts = _relative_parts(relative_path, allow_empty=False)
            _validate_component(parts[-1], set(), relative_path)
            if _is_excluded(relative_path):
                raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
            integrity = self._manager.check_integrity(self._handle)
            unsafe = {
                IntegrityChangeKind.DELETED,
                IntegrityChangeKind.UNEXPECTED,
                IntegrityChangeKind.TYPE_CHANGED,
                IntegrityChangeKind.LIMIT_EXCEEDED,
                IntegrityChangeKind.UNREADABLE,
            }
            if any(change.kind in unsafe for change in integrity.changes):
                raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)

            parent_fd = reader._open_directory(owned.root_fd, parts[:-1])
            try:
                old_info = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                device = os.fstat(owned.root_fd).st_dev
                if (
                    not stat.S_ISREG(old_info.st_mode)
                    or _is_reparse(old_info.st_mode, old_info)
                    or old_info.st_dev != device
                    or old_info.st_nlink != 1
                ):
                    raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
                if old_info.st_size > max_original_bytes:
                    raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
                if integrity.total_bytes - old_info.st_size + len(content) > (
                    self._manager._limits.max_total_bytes
                ):
                    raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
                digest = self._replace_at(
                    reader,
                    owned.root_fd,
                    parent_fd,
                    parts,
                    old_info,
                    expected_sha256,
                    content,
                    max_original_bytes,
                    max_replacement_bytes,
                )
                replacement_completed = True
                return digest
            finally:
                os.close(parent_fd)
        except WorkspaceError:
            raise
        except OSError as error:
            if replacement_completed:
                raise WorkspaceWriteError(
                    WorkspaceErrorCode.STAGING_FAILED, replacement_applied=True
                ) from error
            raise WorkspaceError(WorkspaceErrorCode.STAGING_FAILED) from error

    def _replace_at(
        self,
        reader: WorkspaceReadAccess,
        root_fd: int,
        parent_fd: int,
        parts: tuple[str, ...],
        old_info: os.stat_result,
        expected_sha256: str,
        content: bytes,
        max_original_bytes: int,
        max_replacement_bytes: int,
    ) -> str:
        name = parts[-1]
        source_fd = os.open(name, os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=parent_fd)
        temporary_name = f".repopilot-write-{token_hex(16)}"
        temporary_fd = -1
        temporary_identity: tuple[int, int] | None = None
        renamed = False
        try:
            opened = os.fstat(source_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != old_info.st_dev
                or opened.st_nlink != 1
                or not _same_identity(old_info, opened)
            ):
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            original = _read_all(source_fd, max_original_bytes)
            if hashlib.sha256(original).hexdigest() != expected_sha256:
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            if not _same_stat(opened, os.fstat(source_fd)):
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)

            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            temporary_info = os.fstat(temporary_fd)
            temporary_identity = (temporary_info.st_dev, temporary_info.st_ino)
            change_mode = getattr(os, "fchmod", None)
            if change_mode is None:
                raise WorkspaceError(WorkspaceErrorCode.PLATFORM_UNSUPPORTED)
            change_mode(temporary_fd, 0o600)
            _write_all(temporary_fd, content)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1

            self._manager.read_access(self._handle)
            current_parent = reader._open_directory(root_fd, parts[:-1])
            try:
                named_info = os.stat(name, dir_fd=current_parent, follow_symlinks=False)
                if (
                    not _same_identity(os.fstat(parent_fd), os.fstat(current_parent))
                    or not _same_stat(opened, os.fstat(source_fd))
                    or not _same_stat(opened, named_info)
                ):
                    raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
                os.rename(
                    temporary_name,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                renamed = True
                os.fsync(parent_fd)
            finally:
                os.close(current_parent)

            installed = reader.read_bytes("/".join(parts), max_bytes=max_replacement_bytes)
            digest = hashlib.sha256(installed.content).hexdigest()
            if installed.truncated or installed.content != content:
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            return digest
        except BaseException as error:
            if not renamed and temporary_identity is not None:
                try:
                    named_temporary = os.stat(
                        temporary_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if (named_temporary.st_dev, named_temporary.st_ino) == temporary_identity:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    raise WorkspaceError(WorkspaceErrorCode.CLEANUP_FAILED) from cleanup_error
            if renamed:
                code = (
                    error.code
                    if isinstance(error, WorkspaceError)
                    else WorkspaceErrorCode.STAGING_FAILED
                )
                raise WorkspaceWriteError(code, replacement_applied=True) from error
            if isinstance(error, (KeyboardInterrupt, SystemExit, GeneratorExit, WorkspaceError)):
                raise
            if isinstance(error, OSError):
                raise WorkspaceError(WorkspaceErrorCode.STAGING_FAILED) from error
            raise
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            os.close(source_fd)


def _read_all(descriptor: int, max_bytes: int) -> bytes:
    content = bytearray()
    while len(content) <= max_bytes:
        chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > max_bytes:
        raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
    return bytes(content)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


class WorkspaceWriteError(WorkspaceError):
    """Write failure that reports whether the atomic replacement already occurred."""

    def __init__(self, code: WorkspaceErrorCode, *, replacement_applied: bool) -> None:
        self.replacement_applied = replacement_applied
        super().__init__(code)
