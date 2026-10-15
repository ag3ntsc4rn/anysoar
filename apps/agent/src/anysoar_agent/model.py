"""The model interface: what the agent loop needs from an LLM, independent of provider.

The loop keeps a provider-neutral :data:`Transcript`. A :class:`Model` turns it into one
request, and returns the reply as an :class:`AssistantTurn`. Each turn keeps the provider's
own reply in ``raw``, so a backend can send it back unchanged on the next request (some
providers require their reasoning blocks to be replayed exactly).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

__all__ = [
    "AssistantTurn",
    "Entry",
    "Model",
    "StopReason",
    "ToolCall",
    "ToolResult",
    "ToolResults",
    "ToolSpec",
    "Transcript",
    "UserMessage",
]


@dataclass(frozen=True)
class ToolSpec:
    """A tool the model may call. ``input_schema`` is JSON Schema."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


StopReason = Literal["end", "tool_use", "max_tokens", "refusal"]


@dataclass(frozen=True)
class AssistantTurn:
    """One model reply."""

    stop: StopReason
    text: str = ""
    """What the model said to the user, if anything."""
    tool_calls: tuple[ToolCall, ...] = ()
    reasoning: str = ""
    """A summary of the model's reasoning, if the provider returns one."""
    model: str = ""
    """The model that produced this turn."""
    raw: Any = field(default=None, compare=False, repr=False)
    """The provider's own reply, for replaying it unchanged."""


@dataclass(frozen=True)
class UserMessage:
    text: str


@dataclass(frozen=True)
class ToolResults:
    """Results for every tool call of the preceding assistant turn."""

    results: tuple[ToolResult, ...]


Entry = UserMessage | AssistantTurn | ToolResults
Transcript = Sequence[Entry]


class Model(Protocol):
    """An LLM backend."""

    @property
    def name(self) -> str:
        """Provider and model, e.g. ``claude:claude-opus-5-5``."""
        ...

    async def respond(
        self, system: str, transcript: Transcript, tools: Sequence[ToolSpec]
    ) -> AssistantTurn:
        """Produce the next assistant turn for ``transcript``."""
        ...
