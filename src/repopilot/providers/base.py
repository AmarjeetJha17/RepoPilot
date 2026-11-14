"""Provider interface kept independent from concrete model SDKs."""

from collections.abc import Mapping, Sequence
from typing import Protocol

from repopilot.agent.contracts import ToolCall


class ModelProvider(Protocol):
    """Return normalized model actions without exposing an SDK to the agent."""

    async def next_action(
        self,
        messages: Sequence[Mapping[str, object]],
        tools: Sequence[Mapping[str, object]],
    ) -> ToolCall | str:
        """Return one proposed tool call or text response; provider failures propagate."""
        ...
