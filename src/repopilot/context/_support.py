"""Shared input checks and safe translation at the workspace boundary."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath, PureWindowsPath

from repopilot.context.models import IntelligenceError, IntelligenceErrorCode
from repopilot.sandbox.workspace import WorkspaceError, WorkspaceErrorCode


def relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
        or ":" in value
        or PureWindowsPath(value).drive
        or PureWindowsPath(value).is_absolute()
        or PurePosixPath(value).is_absolute()
    ):
        raise IntelligenceError(IntelligenceErrorCode.INVALID_PATH)
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise IntelligenceError(IntelligenceErrorCode.INVALID_PATH)
    return value


def suffix_filter(values: Iterable[str] | None) -> frozenset[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        values = (values,)
    try:
        suffixes = tuple(values)
    except TypeError as error:
        raise IntelligenceError(IntelligenceErrorCode.INVALID_PATH) from error
    if any(
        not isinstance(value, str)
        or not value.startswith(".")
        or len(value) < 2
        or "/" in value
        or "\\" in value
        for value in suffixes
    ):
        raise IntelligenceError(IntelligenceErrorCode.INVALID_PATH)
    return frozenset(value.casefold() for value in suffixes)


def safe_limit(value: int | None, hard_limit: int, *, allow_zero: bool = False) -> int:
    if value is None:
        return hard_limit
    if type(value) is not int or value < (0 if allow_zero else 1):
        raise IntelligenceError(IntelligenceErrorCode.LIMIT_EXCEEDED)
    return min(value, hard_limit)


def translate_workspace_error(error: WorkspaceError) -> IntelligenceError:
    if error.code is WorkspaceErrorCode.LIMIT_EXCEEDED:
        code = IntelligenceErrorCode.LIMIT_EXCEEDED
    elif error.code is WorkspaceErrorCode.UNSUPPORTED_ENTRY:
        code = IntelligenceErrorCode.UNSUPPORTED_ENTRY
    else:
        code = IntelligenceErrorCode.WORKSPACE_UNAVAILABLE
    return IntelligenceError(code)
