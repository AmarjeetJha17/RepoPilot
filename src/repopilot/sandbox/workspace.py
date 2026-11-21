"""Secure copy-based preparation, integrity checking, and cleanup for repository workspaces."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from repopilot.security.paths import DEFAULT_SENSITIVE_PATTERNS

if TYPE_CHECKING:
    from repopilot.sandbox.read_access import WorkspaceReadAccess

_CHUNK_SIZE = 64 * 1024
_SECRET_CONTENT_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(
        rb"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
        rb"\s*[:=]\s*['\"][^'\"\r\n]{8,}['\"]"
    ),
)
_BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".bin",
        ".dll",
        ".docx",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".mp3",
        ".mp4",
        ".pdf",
        ".png",
        ".pyc",
        ".so",
        ".tar",
        ".whl",
        ".xlsx",
        ".zip",
    }
)
_EXCLUDED_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".cache",
        ".config",
        ".coverage",
        ".docker",
        ".git",
        ".hg",
        ".kube",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".repopilot",
        ".ruff_cache",
        ".secrets",
        ".ssh",
        ".tox",
        ".uv-cache",
        ".venv",
        "htmlcov",
        "__pycache__",
        "build",
        "dist",
        "env",
        "logs",
        "node_modules",
        "venv",
        "virtualenv",
    }
)
_SENSITIVE_NAMES = frozenset({".netrc", ".npmrc", ".pypirc"})
_SENSITIVE_SUFFIXES = (".asc", ".gpg", ".kdbx", ".ppk")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOATIME = getattr(os, "O_NOATIME", 0)
_SECURE_DESCRIPTOR_IO = (
    sys.platform.startswith("linux")
    and bool(_NOFOLLOW and _DIRECTORY and _NOATIME)
    and hasattr(os, "fchmod")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.rmdir in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and os.scandir in os.supports_fd
)


class WorkspaceErrorCode(StrEnum):
    """Stable safe failure categories for workspace operations."""

    PLATFORM_UNSUPPORTED = "platform_unsupported"
    SOURCE_ROOT_INVALID = "source_root_invalid"
    DESTINATION_UNSAFE = "destination_unsafe"
    UNSUPPORTED_ENTRY = "unsupported_entry"
    LIMIT_EXCEEDED = "limit_exceeded"
    SOURCE_CHANGED = "source_changed_during_copy"
    STAGING_FAILED = "staging_failed"
    OWNERSHIP_MISMATCH = "ownership_mismatch"
    CLEANUP_FAILED = "cleanup_failed"


class WorkspaceError(RuntimeError):
    """Workspace failure that reports a stable code without echoing private paths."""

    def __init__(self, code: WorkspaceErrorCode) -> None:
        self.code = code
        super().__init__(f"Repository workspace operation failed: {code.value}.")


@dataclass(frozen=True, slots=True)
class WorkspaceLimits:
    """Bound staged file size, aggregate size, file count, and directory depth."""

    max_file_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_files: int = 10_000
    max_depth: int = 32

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 0 for value in self.as_tuple()):
            raise ValueError("Workspace limits must be non-negative integers.")
        if self.max_file_bytes == 0 or self.max_files == 0:
            raise ValueError("File size and file count limits must be positive.")

    def as_tuple(self) -> tuple[int, int, int, int]:
        return (self.max_file_bytes, self.max_total_bytes, self.max_files, self.max_depth)


@dataclass(frozen=True, slots=True)
class WorkspaceIdentity:
    """Opaque in-process identifier; not a cryptographic authorization token."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("Workspace identity must contain a UUID.")


class WorkspacePreparationStatus(StrEnum):
    """Preparation status exposed on a successfully returned handle."""

    PREPARED = "prepared"


class WorkspaceCleanupState(StrEnum):
    """Cleanup state maintained by the owning manager."""

    ACTIVE = "active"
    CLEANED = "cleaned"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class BaselineFile:
    """One staged relative file and its content-integrity metadata."""

    path: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or not self.path
            or self.path.startswith("/")
            or "\\" in self.path
            or ":" in self.path
            or any(part in {"", ".", ".."} for part in self.path.split("/"))
            or type(self.size_bytes) is not int
            or self.size_bytes < 0
            or not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("Baseline entries require safe relative paths and SHA-256 metadata.")


@dataclass(frozen=True, slots=True)
class BaselineManifest:
    """Versioned deterministic inventory; it contains no source root or file contents."""

    format_version: int
    files: tuple[BaselineFile, ...]
    total_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.format_version) is not int
            or self.format_version != 1
            or not isinstance(self.files, tuple)
            or any(not isinstance(item, BaselineFile) for item in self.files)
            or tuple(sorted(self.files, key=lambda item: item.path)) != self.files
            or len({item.path for item in self.files}) != len(self.files)
            or type(self.total_bytes) is not int
            or self.total_bytes != sum(item.size_bytes for item in self.files)
        ):
            raise ValueError("Baseline manifest metadata is inconsistent.")

    @property
    def file_count(self) -> int:
        return len(self.files)

    def to_json(self) -> str:
        """Serialize with stable key and file ordering for reproducible comparisons."""
        return json.dumps(
            {
                "format_version": self.format_version,
                "files": [
                    {"path": item.path, "sha256": item.sha256, "size_bytes": item.size_bytes}
                    for item in self.files
                ],
                "total_bytes": self.total_bytes,
                "total_files": self.file_count,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceHandle:
    """Caller reference to a prepared workspace; cleanup remains manager-owned."""

    identity: WorkspaceIdentity
    source_root: Path
    staging_root: Path
    status: WorkspacePreparationStatus
    baseline: BaselineManifest

    def __post_init__(self) -> None:
        if (
            not isinstance(self.identity, WorkspaceIdentity)
            or not isinstance(self.source_root, Path)
            or not isinstance(self.staging_root, Path)
            or self.status is not WorkspacePreparationStatus.PREPARED
            or not isinstance(self.baseline, BaselineManifest)
        ):
            raise TypeError("Workspace handle fields do not match the typed contract.")


class IntegrityChangeKind(StrEnum):
    """Detected differences between the staged tree and its baseline."""

    MODIFIED = "modified"
    DELETED = "deleted"
    UNEXPECTED = "unexpected"
    TYPE_CHANGED = "type_changed"
    LIMIT_EXCEEDED = "limit_exceeded"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class IntegrityChange:
    """One root-relative integrity discrepancy, without file content."""

    path: str
    kind: IntegrityChangeKind


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """Read-only staged integrity result, not evidence of code correctness."""

    changes: tuple[IntegrityChange, ...]
    file_count: int
    total_bytes: int

    @property
    def matches_baseline(self) -> bool:
        return not self.changes


@dataclass(slots=True)
class _CopyState:
    limits: WorkspaceLimits
    files: list[BaselineFile] = field(default_factory=list)
    total_bytes: int = 0
    seen_names: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _OwnedWorkspace:
    handle: WorkspaceHandle
    parent_fd: int
    root_fd: int
    directory_name: str
    root_identity: tuple[int, int]
    cleanup_state: WorkspaceCleanupState = WorkspaceCleanupState.ACTIVE


class WorkspaceManager:
    """Copy eligible source files into a disposable, descriptor-owned workspace.

    Secure preparation requires Linux directory-relative O_NOFOLLOW and O_NOATIME operations.
    Other platforms fail closed; use Linux or WSL2.
    """

    def __init__(
        self,
        *,
        temp_root: Path | None = None,
        limits: WorkspaceLimits | None = None,
    ) -> None:
        self._temp_root = Path(tempfile.gettempdir()) if temp_root is None else temp_root
        self._limits = WorkspaceLimits() if limits is None else limits
        self._workspaces: dict[WorkspaceIdentity, _OwnedWorkspace] = {}
        self._closed = False

    def __enter__(self) -> WorkspaceManager:
        if self._closed:
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self.close()
        except WorkspaceError as cleanup_error:
            if isinstance(exc, BaseException):
                raise BaseExceptionGroup(
                    "Workspace body and cleanup both failed.", [exc, cleanup_error]
                ) from cleanup_error
            raise

    def prepare(self, source_root: Path) -> WorkspaceHandle:
        """Create an isolated copy, rejecting unsupported paths and source races."""
        if self._closed:
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        source = _absolute_directory_path(source_root, WorkspaceErrorCode.SOURCE_ROOT_INVALID)
        destination = _absolute_directory_path(
            self._temp_root, WorkspaceErrorCode.DESTINATION_UNSAFE
        )
        if _is_within(destination, source):
            raise WorkspaceError(WorkspaceErrorCode.DESTINATION_UNSAFE)
        if not _SECURE_DESCRIPTOR_IO:
            raise WorkspaceError(WorkspaceErrorCode.PLATFORM_UNSUPPORTED)

        source_fd = parent_fd = root_fd = -1
        directory_name: str | None = None
        root_identity: tuple[int, int] | None = None
        try:
            try:
                source_fd = _open_absolute_directory(source, no_atime=True)
            except OSError as error:
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_ROOT_INVALID) from error
            source_before = os.fstat(source_fd)
            source_mounts = _mount_points_under(source, _read_mount_points())
            if source_mounts:
                raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
            try:
                parent_fd = _open_absolute_directory(destination)
            except OSError as error:
                raise WorkspaceError(WorkspaceErrorCode.DESTINATION_UNSAFE) from error
            directory_name, root_fd, root_identity = _make_private_directory(parent_fd)
            _chmod_descriptor(root_fd, 0o700)
            staging = destination / directory_name
            if _is_within(staging, source) or _is_within(source, staging):
                raise WorkspaceError(WorkspaceErrorCode.DESTINATION_UNSAFE)

            copy_state = _CopyState(self._limits)
            _copy_directory(source_fd, root_fd, "", 0, copy_state, source_before.st_dev)
            if not _same_stat(
                source_before, os.fstat(source_fd)
            ) or source_mounts != _mount_points_under(source, _read_mount_points()):
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            baseline = BaselineManifest(
                1,
                tuple(sorted(copy_state.files, key=lambda item: item.path)),
                copy_state.total_bytes,
            )
            handle = WorkspaceHandle(
                WorkspaceIdentity(),
                source,
                staging,
                WorkspacePreparationStatus.PREPARED,
                baseline,
            )
            owned = _OwnedWorkspace(
                handle,
                parent_fd,
                root_fd,
                directory_name,
                root_identity,
            )
            self._workspaces[handle.identity] = owned
            parent_fd = root_fd = -1
            return handle
        except BaseException as error:
            if parent_fd >= 0 and directory_name is not None and root_identity is not None:
                try:
                    _remove_owned_directory(
                        parent_fd,
                        directory_name,
                        root_fd,
                        root_identity,
                        destination / directory_name,
                    )
                except OSError as cleanup_error:
                    raise WorkspaceError(WorkspaceErrorCode.CLEANUP_FAILED) from cleanup_error
            if isinstance(error, (KeyboardInterrupt, SystemExit, GeneratorExit, WorkspaceError)):
                raise
            if isinstance(error, OSError):
                raise WorkspaceError(WorkspaceErrorCode.STAGING_FAILED) from error
            raise
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
            if root_fd >= 0:
                os.close(root_fd)

    def check_integrity(self, handle: WorkspaceHandle) -> IntegrityReport:
        """Compare staging files to the baseline without following links or modifying data."""
        owned = self._owned(handle)
        if owned.cleanup_state is not WorkspaceCleanupState.ACTIVE:
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        if not _root_name_matches(owned):
            return IntegrityReport((IntegrityChange(".", IntegrityChangeKind.TYPE_CHANGED),), 0, 0)
        mounted = _mount_points_under(handle.staging_root, _read_mount_points())
        if mounted:
            mounted_changes = tuple(
                IntegrityChange(
                    point.relative_to(handle.staging_root).as_posix(),
                    IntegrityChangeKind.TYPE_CHANGED,
                )
                for point in mounted
            )
            return IntegrityReport(mounted_changes, 0, 0)
        baseline = {item.path: item for item in handle.baseline.files}
        changes: list[IntegrityChange] = []
        seen: set[str] = set()
        totals = [0, 0]
        _inspect_directory(
            owned.root_fd,
            "",
            baseline,
            seen,
            changes,
            totals,
            self._limits,
            0,
            os.fstat(owned.root_fd).st_dev,
        )
        changes.extend(
            IntegrityChange(path, IntegrityChangeKind.DELETED)
            for path in sorted(baseline.keys() - seen)
        )
        changes.sort(key=lambda item: (item.path, item.kind.value))
        return IntegrityReport(tuple(changes), totals[0], totals[1])

    def cleanup(self, handle: WorkspaceHandle) -> WorkspaceCleanupState:
        """Remove only the exact workspace registered by this manager; safe to repeat."""
        owned = self._owned(handle)
        if owned.cleanup_state is WorkspaceCleanupState.CLEANED:
            return WorkspaceCleanupState.CLEANED
        try:
            _remove_owned_directory(
                owned.parent_fd,
                owned.directory_name,
                owned.root_fd,
                owned.root_identity,
                owned.handle.staging_root,
            )
        except OSError as error:
            owned.cleanup_state = WorkspaceCleanupState.FAILED
            raise WorkspaceError(WorkspaceErrorCode.CLEANUP_FAILED) from error
        os.close(owned.root_fd)
        os.close(owned.parent_fd)
        owned.cleanup_state = WorkspaceCleanupState.CLEANED
        return owned.cleanup_state

    def cleanup_state(self, handle: WorkspaceHandle) -> WorkspaceCleanupState:
        """Return the manager's recorded lifecycle state for its exact handle."""
        return self._owned(handle).cleanup_state

    def read_access(self, handle: WorkspaceHandle) -> WorkspaceReadAccess:
        """Issue bounded read-only access only for this manager's active workspace."""
        if not _SECURE_DESCRIPTOR_IO:
            raise WorkspaceError(WorkspaceErrorCode.PLATFORM_UNSUPPORTED)
        owned = self._owned(handle)
        if owned.cleanup_state is not WorkspaceCleanupState.ACTIVE or not _root_name_matches(owned):
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        if _mount_points_under(handle.staging_root, _read_mount_points()):
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
        from repopilot.sandbox.read_access import WorkspaceReadAccess

        return WorkspaceReadAccess(self, handle)

    def close(self) -> None:
        """Clean every manager-owned workspace and report failures after trying all."""
        if self._closed:
            return
        errors: list[Exception] = []
        for owned in tuple(self._workspaces.values()):
            if owned.cleanup_state is WorkspaceCleanupState.CLEANED:
                continue
            try:
                self.cleanup(owned.handle)
            except WorkspaceError as error:
                errors.append(error)
        self._closed = not errors
        if errors:
            raise WorkspaceError(WorkspaceErrorCode.CLEANUP_FAILED) from errors[0]

    def _owned(self, handle: WorkspaceHandle) -> _OwnedWorkspace:
        if not isinstance(handle, WorkspaceHandle):
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        owned = self._workspaces.get(handle.identity)
        if owned is None or owned.handle is not handle:
            raise WorkspaceError(WorkspaceErrorCode.OWNERSHIP_MISMATCH)
        return owned


def _absolute_directory_path(path: Path, error_code: WorkspaceErrorCode) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or ".." in path.parts
        or str(path).startswith(("//", "\\\\?\\", "\\\\.\\"))
        or PureWindowsPath(str(path)).drive.startswith("\\\\")
    ):
        raise WorkspaceError(error_code)
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _read_mount_points() -> tuple[Path, ...]:
    if not sys.platform.startswith("linux"):
        return ()
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise WorkspaceError(WorkspaceErrorCode.PLATFORM_UNSUPPORTED) from error
    mount_points = []
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            raise WorkspaceError(WorkspaceErrorCode.PLATFORM_UNSUPPORTED)
        mount_path = fields[4]
        for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n")):
            mount_path = mount_path.replace(encoded, decoded)
        mount_points.append(Path(mount_path.replace("\\134", "\\")))
    return tuple(mount_points)


def _mount_points_under(root: Path, mount_points: tuple[Path, ...]) -> tuple[Path, ...]:
    return tuple(
        sorted(
            {point for point in mount_points if point != root and _is_within(point, root)},
            key=str,
        )
    )


def _open_absolute_directory(path: Path, *, no_atime: bool = False) -> int:
    descriptor = os.open(path.anchor, _directory_flags())
    try:
        components = path.parts[1:]
        for index, component in enumerate(components):
            child = os.open(
                component,
                _directory_flags(no_atime=no_atime and index == len(components) - 1),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_flags(*, no_atime: bool = False) -> int:
    return os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC | (_NOATIME if no_atime else 0)


def _make_private_directory(parent_fd: int) -> tuple[str, int, tuple[int, int]]:
    for _ in range(10):
        name = f"repopilot-workspace-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
            info = os.fstat(descriptor)
            return name, descriptor, (info.st_dev, info.st_ino)
        except BaseException:
            os.rmdir(name, dir_fd=parent_fd)
            raise
    raise WorkspaceError(WorkspaceErrorCode.STAGING_FAILED)


def _copy_directory(
    source_fd: int,
    destination_fd: int,
    prefix: str,
    depth: int,
    state: _CopyState,
    source_device: int,
) -> None:
    before = os.fstat(source_fd)
    for name in _entry_names(source_fd):
        relative = f"{prefix}/{name}" if prefix else name
        _validate_component(name, state.seen_names, relative)
        if _is_excluded(relative):
            continue
        source_info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if source_info.st_dev != source_device or (
            stat.S_ISREG(source_info.st_mode) and source_info.st_nlink != 1
        ):
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
        if _is_reparse(source_info.st_mode, source_info):
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
        if stat.S_ISDIR(source_info.st_mode):
            child_depth = depth + 1
            if child_depth > state.limits.max_depth:
                raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
            child_source_fd = os.open(name, _directory_flags(no_atime=True), dir_fd=source_fd)
            if not _same_identity(source_info, os.fstat(child_source_fd)):
                os.close(child_source_fd)
                raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
            os.mkdir(name, 0o700, dir_fd=destination_fd)
            child_destination_fd = os.open(name, _directory_flags(), dir_fd=destination_fd)
            try:
                _copy_directory(
                    child_source_fd,
                    child_destination_fd,
                    relative,
                    child_depth,
                    state,
                    source_device,
                )
            finally:
                os.close(child_source_fd)
                os.close(child_destination_fd)
        elif stat.S_ISREG(source_info.st_mode):
            result = _copy_regular_file(
                source_fd,
                destination_fd,
                name,
                source_info,
                state,
            )
            if result is not None:
                size, digest = result
                state.files.append(BaselineFile(relative, size, digest))
        else:
            raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
    if not _same_stat(before, os.fstat(source_fd)):
        raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)


def _copy_regular_file(
    source_dir_fd: int,
    destination_dir_fd: int,
    name: str,
    source_info: os.stat_result,
    state: _CopyState,
) -> tuple[int, str] | None:
    if source_info.st_size > state.limits.max_file_bytes:
        raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
    if source_info.st_size + state.total_bytes > state.limits.max_total_bytes:
        raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
    if Path(name).suffix.casefold() in _BINARY_SUFFIXES:
        return None

    source_fd = os.open(name, os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NOATIME, dir_fd=source_dir_fd)
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(source_info, opened):
            raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
        if len(state.files) >= state.limits.max_files:
            raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
        total = 0
        binary = False
        content = bytearray()
        while chunk := os.read(source_fd, _CHUNK_SIZE):
            total += len(chunk)
            if total > state.limits.max_file_bytes:
                raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
            if total + state.total_bytes > state.limits.max_total_bytes:
                raise WorkspaceError(WorkspaceErrorCode.LIMIT_EXCEEDED)
            binary |= b"\x00" in chunk
            content.extend(chunk)
        after = os.fstat(source_fd)
        if total != opened.st_size or not _same_stat(opened, after):
            raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
        if binary or _contains_known_secret(content):
            return None

        destination_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
            0o600,
            dir_fd=destination_dir_fd,
        )
        _chmod_descriptor(destination_fd, 0o600)
        _write_all(destination_fd, content)
        if not _same_stat(opened, os.fstat(source_fd)):
            raise WorkspaceError(WorkspaceErrorCode.SOURCE_CHANGED)
        state.total_bytes += total
        return total, hashlib.sha256(content).hexdigest()
    except BaseException:
        if destination_fd >= 0:
            os.close(destination_fd)
            destination_fd = -1
            os.unlink(name, dir_fd=destination_dir_fd)
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _contains_known_secret(content: bytes | bytearray) -> bool:
    return any(pattern.search(content) is not None for pattern in _SECRET_CONTENT_PATTERNS)


def _write_all(descriptor: int, content: bytes | bytearray) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("Staging write made no progress.")
        view = view[written:]


def _chmod_descriptor(descriptor: int, mode: int) -> None:
    change_mode = getattr(os, "fchmod", None)
    if change_mode is None:
        raise WorkspaceError(WorkspaceErrorCode.PLATFORM_UNSUPPORTED)
    change_mode(descriptor, mode)


def _inspect_directory(
    directory_fd: int,
    prefix: str,
    baseline: dict[str, BaselineFile],
    seen: set[str],
    changes: list[IntegrityChange],
    totals: list[int],
    limits: WorkspaceLimits,
    depth: int,
    device: int,
) -> None:
    for name in _entry_names(directory_fd):
        relative = f"{prefix}/{name}" if prefix else name
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            changes.append(IntegrityChange(relative, IntegrityChangeKind.UNREADABLE))
            continue
        expected = baseline.get(relative)
        if expected is not None:
            seen.add(relative)
        if _is_reparse(info.st_mode, info) or stat.S_ISLNK(info.st_mode) or info.st_dev != device:
            changes.append(IntegrityChange(relative, IntegrityChangeKind.TYPE_CHANGED))
        elif stat.S_ISDIR(info.st_mode):
            if expected is not None:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.TYPE_CHANGED))
            if depth >= limits.max_depth:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.LIMIT_EXCEEDED))
                continue
            child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
            try:
                _inspect_directory(
                    child_fd,
                    relative,
                    baseline,
                    seen,
                    changes,
                    totals,
                    limits,
                    depth + 1,
                    device,
                )
            except OSError:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.UNREADABLE))
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.TYPE_CHANGED))
                continue
            totals[0] += 1
            totals[1] += info.st_size
            if totals[0] > limits.max_files or totals[1] > limits.max_total_bytes:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.LIMIT_EXCEEDED))
                continue
            if info.st_size > limits.max_file_bytes:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.LIMIT_EXCEEDED))
                continue
            if expected is None:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.UNEXPECTED))
                continue
            try:
                digest = _hash_file_at(directory_fd, name, info)
            except OSError:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.UNREADABLE))
                continue
            if info.st_size != expected.size_bytes or digest != expected.sha256:
                changes.append(IntegrityChange(relative, IntegrityChangeKind.MODIFIED))
        else:
            changes.append(IntegrityChange(relative, IntegrityChangeKind.TYPE_CHANGED))


def _hash_file_at(directory_fd: int, name: str, expected: os.stat_result) -> str:
    descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(expected, opened):
            raise OSError("Staged file changed during integrity check.")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, _CHUNK_SIZE):
            digest.update(chunk)
        if not _same_stat(opened, os.fstat(descriptor)):
            raise OSError("Staged file changed during integrity check.")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _remove_owned_directory(
    parent_fd: int,
    name: str,
    root_fd: int,
    root_identity: tuple[int, int] | None,
    root_path: Path,
) -> None:
    opened_here = root_fd < 0
    if opened_here:
        root_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    root_info = os.fstat(root_fd)
    if root_identity != (root_info.st_dev, root_info.st_ino):
        if opened_here:
            os.close(root_fd)
        raise OSError("Owned staging directory identity changed.")
    try:
        named_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(named_info.st_mode) or not _same_identity(named_info, root_info):
            raise OSError("Owned staging path was replaced.")
        try:
            if _mount_points_under(root_path, _read_mount_points()):
                raise OSError("Staging cleanup refuses mounted descendants.")
        except WorkspaceError as error:
            raise OSError("Staging cleanup could not verify mount boundaries.") from error
        _remove_directory_contents(root_fd, root_info.st_dev)
        named_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(named_info.st_mode) or not _same_identity(named_info, root_info):
            raise OSError("Owned staging path was replaced during cleanup.")
        try:
            if _mount_points_under(root_path, _read_mount_points()):
                raise OSError("Staging cleanup refuses mounted descendants.")
        except WorkspaceError as error:
            raise OSError("Staging cleanup could not verify mount boundaries.") from error
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        if opened_here:
            os.close(root_fd)


def _remove_directory_contents(directory_fd: int, device: int) -> None:
    for name in _entry_names(directory_fd):
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode) and not _is_reparse(info.st_mode, info):
            if info.st_dev != device:
                raise OSError("Staging cleanup refuses a mounted directory.")
            child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
            try:
                if not _same_identity(info, os.fstat(child_fd)):
                    raise OSError("Staging entry changed during cleanup.")
                _remove_directory_contents(child_fd, device)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _root_name_matches(owned: _OwnedWorkspace) -> bool:
    try:
        info = os.stat(owned.directory_name, dir_fd=owned.parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and _same_identity(info, os.fstat(owned.root_fd))


def _entry_names(directory_fd: int) -> list[str]:
    with os.scandir(directory_fd) as entries:
        return sorted((entry.name for entry in entries), key=lambda name: (name.casefold(), name))


def _validate_component(name: str, seen_names: set[str], relative: str) -> None:
    stem = name.split(".", 1)[0].casefold()
    if (
        not name
        or name in {".", ".."}
        or "\\" in name
        or ":" in name
        or any(character in '<>"|?*' or ord(character) < 32 for character in name)
        or name.endswith((".", " "))
        or stem in _WINDOWS_RESERVED_NAMES
    ):
        raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
    normalized = relative.casefold()
    if normalized in seen_names:
        raise WorkspaceError(WorkspaceErrorCode.UNSUPPORTED_ENTRY)
    seen_names.add(normalized)


def _is_excluded(relative: str) -> bool:
    lowered = relative.casefold()
    parts = lowered.split("/")
    if any(part in _EXCLUDED_NAMES for part in parts):
        return True
    name = parts[-1]
    if name.startswith(".env"):
        return True
    if (
        name in _SENSITIVE_NAMES
        or name == "coverage.xml"
        or name.endswith((".log", ".db", ".sqlite", ".sqlite3", ".egg-info"))
    ):
        return True
    if name.endswith(_SENSITIVE_SUFFIXES):
        return True
    if any(
        token in name
        for token in (
            "credential",
            "secret",
            "service-account",
            "password",
            "token",
            "api_key",
            "api-key",
            "apikey",
            "private_key",
            "private-key",
        )
    ):
        return True
    return any(
        fnmatchcase(lowered, pattern.casefold())
        or any(fnmatchcase(part, pattern.removeprefix("**/").casefold()) for part in parts)
        for pattern in DEFAULT_SENSITIVE_PATTERNS
    )


def _is_reparse(mode: int, info: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(reparse_flag and attributes & reparse_flag) or stat.S_ISLNK(mode)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_identity(left, right) and (
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )
