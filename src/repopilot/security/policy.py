"""Policy decisions remain independent from tool execution and model semantics."""

from enum import StrEnum
from pathlib import Path
from typing import Protocol

from repopilot.agent.contracts import ToolCall


class PolicyDecision(StrEnum):
    """Possible outcomes from a deterministic authorization check."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "approval"


class PolicyEngine(Protocol):
    """Authorize a normalized request against a trusted workspace boundary."""

    def authorize(self, call: ToolCall, workspace: Path) -> PolicyDecision:
        """Return an authorization outcome; this interface grants no permission itself."""
        ...
