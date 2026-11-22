"""Trusted local terminal presentation for exact patch approval."""

from __future__ import annotations

import sys
from collections.abc import Callable
from unicodedata import category

from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

from repopilot.security.approval import (
    ApprovalReasonCode,
    ReviewedPatchManifest,
    TrustedApprovalDecision,
)


class RichTerminalApproval:
    """Ask an interactive local user to approve one complete reviewed diff."""

    def __init__(
        self,
        *,
        console: Console | None = None,
        input_isatty: Callable[[], bool] | None = None,
    ) -> None:
        self._console = console or Console()
        self._input_isatty = input_isatty or (lambda: sys.stdin.isatty())

    def confirm(
        self,
        manifest: ReviewedPatchManifest,
        diff: str,
        *,
        truncated: bool,
        repository_label: str,
    ) -> TrustedApprovalDecision:
        """Display complete plain-text diff and require the explicit response `y`."""
        if truncated:
            return TrustedApprovalDecision(False, ApprovalReasonCode.PREVIEW_TRUNCATED)
        if not self._console.is_terminal or not self._input_isatty():
            return TrustedApprovalDecision(False, ApprovalReasonCode.NONINTERACTIVE)
        self._console.print(f"Repository: {repository_label}")
        self._console.print(f"Repository identity: {manifest.repository_identity}")
        self._console.print(f"Changed files ({len(manifest.entries)}):")
        for entry in manifest.entries:
            self._console.print(Text(f"  {entry.path}"))
        self._console.print("Complete patch preview:")
        self._console.print(Text(_escape_controls(diff), no_wrap=False, overflow="fold"))
        self._console.print(f"Manifest digest: {manifest.digest}")
        try:
            answer = Prompt.ask(
                "Apply this patch to this repository? [y/N]",
                default="N",
                console=self._console,
            )
        except (EOFError, KeyboardInterrupt):
            return TrustedApprovalDecision(False, ApprovalReasonCode.CANCELLED)
        if answer.strip().casefold() == "y":
            return TrustedApprovalDecision(True)
        return TrustedApprovalDecision(False, ApprovalReasonCode.USER_DENIED)


def _escape_controls(value: str) -> str:
    """Render terminal control and bidi format characters visibly, never execute them."""
    visible: list[str] = []
    for character in value:
        if character in "\n\t" or not category(character).startswith("C"):
            visible.append(character)
        else:
            codepoint = ord(character)
            visible.append(
                f"\\x{codepoint:02x}"
                if codepoint <= 0xFF
                else f"\\u{codepoint:04x}"
                if codepoint <= 0xFFFF
                else f"\\U{codepoint:08x}"
            )
    return "".join(visible)
