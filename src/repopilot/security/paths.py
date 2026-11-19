"""Read-only canonical path checks for policy decisions."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath, PureWindowsPath

DEFAULT_SENSITIVE_PATTERNS = (
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    ".ssh",
    ".ssh/**",
    "**/.ssh/**",
    ".aws",
    ".aws/**",
    "**/.aws/**",
    ".kube",
    ".kube/**",
    "**/.kube/**",
    ".azure",
    ".azure/**",
    "**/.azure/**",
    ".config/gcloud/**",
    "**/.config/gcloud/**",
    ".docker/config.json",
    "**/.docker/config.json",
    ".git/**",
    "**/.git/**",
    "*.pem",
    "**/*.pem",
    "*.key",
    "**/*.key",
    "*.p12",
    "**/*.p12",
    "*.pfx",
    "**/*.pfx",
    "id_rsa*",
    "**/id_rsa*",
    "id_ed25519*",
    "**/id_ed25519*",
    "id_ecdsa*",
    "**/id_ecdsa*",
    "id_dsa*",
    "**/id_dsa*",
    "*credentials*",
    "**/*credentials*",
    "*service-account*.json",
    "**/*service-account*.json",
)


class PathFailure(StrEnum):
    """Safe path failure categories used by the policy layer."""

    INVALID = "invalid"
    OUTSIDE = "outside"
    SENSITIVE = "sensitive"
    TYPE_MISMATCH = "type_mismatch"
    MISSING = "missing"
    SYMLINK = "symlink"


class PathAuthorizationError(ValueError):
    """A resource path failed a policy check without echoing the input path."""

    def __init__(self, failure: PathFailure) -> None:
        self.failure = failure
        super().__init__(f"Resource path rejected: {failure.value}.")


def authorize_resource_path(
    root: Path,
    value: object,
    *,
    resource_type: str,
    sensitive_patterns: Iterable[str],
    allow_missing: bool,
    forbid_symlinks: bool,
) -> str:
    """Return a normalized root-relative resource path after read-only checks.

    This check is intentionally not race-free; callers must revalidate immediately before use.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PathAuthorizationError(PathFailure.INVALID)

    windows_path = PureWindowsPath(value)
    posix_path = PurePosixPath(value.replace("\\", "/"))
    if windows_path.drive or windows_path.is_absolute() or posix_path.is_absolute():
        raise PathAuthorizationError(PathFailure.OUTSIDE)
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if ":" in value or any(part == ".." for part in parts):
        raise PathAuthorizationError(PathFailure.INVALID)
    parts = [part for part in parts if part not in ("", ".")]
    if not parts and resource_type != "directory":
        raise PathAuthorizationError(PathFailure.TYPE_MISMATCH)
    relative = PurePosixPath(*parts) if parts else PurePosixPath(".")
    relative_text = relative.as_posix()
    if _is_sensitive(relative_text, sensitive_patterns):
        raise PathAuthorizationError(PathFailure.SENSITIVE)

    try:
        canonical_root = root.resolve(strict=True)
        candidate = canonical_root.joinpath(*parts).resolve(strict=False)
        candidate.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise PathAuthorizationError(PathFailure.OUTSIDE) from error

    if forbid_symlinks and _contains_symlink(canonical_root.joinpath(*parts), canonical_root):
        raise PathAuthorizationError(PathFailure.SYMLINK)
    exists = candidate.exists()
    if not exists and not allow_missing:
        raise PathAuthorizationError(PathFailure.MISSING)
    if exists and (
        (resource_type == "file" and not candidate.is_file())
        or (resource_type == "directory" and not candidate.is_dir())
    ):
        raise PathAuthorizationError(PathFailure.TYPE_MISMATCH)
    return relative_text


def _contains_symlink(candidate: Path, root: Path) -> bool:
    current = root
    for part in candidate.relative_to(root).parts:
        current = current / part
        if current.is_symlink() or current.is_junction():
            return True
    return False


def _is_sensitive(path: str, patterns: Iterable[str]) -> bool:
    lowered = path.casefold()
    if any(
        part == ".env"
        or part.startswith(".env.")
        or part in {".ssh", ".aws", ".kube", ".git"}
        or part == ".azure"
        or part.endswith((".pem", ".key", ".p12", ".pfx", ".ppk"))
        or part.startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
        or "credential" in part
        or part == "service-account.json"
        for part in lowered.split("/")
    ):
        return True
    return any(fnmatchcase(lowered, pattern.replace("\\", "/").casefold()) for pattern in patterns)
