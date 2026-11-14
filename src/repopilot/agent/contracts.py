"""Provider-to-agent and agent-to-tool message contracts."""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ToolCall:
    """Provider-proposed request shape; construction does not validate untrusted values."""

    id: str
    name: str
    arguments: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Tool result shape; producers are responsible for enforcing output limits."""

    call_id: str
    ok: bool
    output: str
    truncated: bool = False
