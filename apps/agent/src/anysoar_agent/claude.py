"""Claude backend for the agent, using the Anthropic Messages API.

Needs the ``claude`` extra (``anthropic``). Credentials come from the environment
(``ANTHROPIC_API_KEY``, or an ``ant auth login`` profile).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from anthropic import AsyncAnthropic, omit
from anthropic.types.beta import (
    BetaContentBlock,
    BetaMessage,
    BetaMessageParam,
    BetaTextBlockParam,
    BetaToolParam,
    BetaToolResultBlockParam,
    BetaToolUseBlockParam,
)

from anysoar_agent.model import (
    AssistantTurn,
    StopReason,
    ToolCall,
    ToolResults,
    ToolSpec,
    Transcript,
    UserMessage,
)

__all__ = ["DEFAULT_MODEL", "ClaudeModel"]

DEFAULT_MODEL = "claude-opus-5-5"

Effort = Literal["low", "medium", "high", "xhigh", "max"]

_STOP_REASONS: dict[str | None, StopReason] = {
    "end_turn": "end",
    "stop_sequence": "end",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "refusal": "refusal",
    # The agent uses no server-side tools, so a paused turn has nothing to resume.
    "pause_turn": "end",
}


@dataclass(frozen=True)
class _ClaudeContent:
    """A Claude reply's content blocks, replayed unchanged on later requests."""

    blocks: tuple[BetaContentBlock, ...]


class ClaudeModel:
    """Claude via the Messages API.

    - Adaptive thinking with summarized display, so the agent can show its reasoning.
    - ``effort`` is set explicitly: agentic work does well at ``high``.
    - Server-side fallbacks (``fallbacks="default"``): if a safety classifier declines a
      request, the API retries it on a recommended fallback model in the same call. A
      turn's ``model`` reports which model actually answered.
    - Automatic prompt caching: the tools and system prompt are stable across turns.
    - Claude's replies are sent back unchanged, including thinking blocks.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        client: AsyncAnthropic | None = None,
        effort: Effort = "high",
        max_tokens: int = 16000,
        fallbacks: bool = True,
    ) -> None:
        self.model = model
        self.client = client or AsyncAnthropic()
        self.effort: Effort = effort
        self.max_tokens = max_tokens
        self.fallbacks = fallbacks

    @property
    def name(self) -> str:
        return f"claude:{self.model}"

    async def respond(
        self, system: str, transcript: Transcript, tools: Sequence[ToolSpec]
    ) -> AssistantTurn:
        response = await self.client.beta.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=to_messages(transcript),
            tools=[to_tool(t) for t in tools],
            thinking={"type": "adaptive", "display": "summarized"},
            output_config={"effort": self.effort},
            cache_control={"type": "ephemeral"},
            betas=["server-side-fallback-2026-07-01"] if self.fallbacks else omit,
            fallbacks="default" if self.fallbacks else omit,
        )
        return to_turn(response)


def to_tool(spec: ToolSpec) -> BetaToolParam:
    return {
        "name": spec.name,
        "description": spec.description,
        "input_schema": spec.input_schema,
    }


def to_messages(transcript: Transcript) -> list[BetaMessageParam]:
    """Convert the neutral transcript to Messages API messages."""
    messages: list[BetaMessageParam] = []
    for entry in transcript:
        if isinstance(entry, UserMessage):
            messages.append({"role": "user", "content": entry.text})
        elif isinstance(entry, ToolResults):
            results: list[BetaToolResultBlockParam] = [
                {
                    "type": "tool_result",
                    "tool_use_id": r.call_id,
                    "content": r.content,
                    "is_error": r.is_error,
                }
                for r in entry.results
            ]
            messages.append({"role": "user", "content": results})
        elif isinstance(entry.raw, _ClaudeContent):
            messages.append({"role": "assistant", "content": list(entry.raw.blocks)})
        else:
            # A turn from another provider: keep what it said and the calls it made.
            content: list[BetaTextBlockParam | BetaToolUseBlockParam] = []
            if entry.text:
                content.append({"type": "text", "text": entry.text})
            content.extend(
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                for c in entry.tool_calls
            )
            messages.append({"role": "assistant", "content": content})
    return messages


def to_turn(response: BetaMessage) -> AssistantTurn:
    """Convert a Messages API response to a neutral assistant turn."""
    texts: list[str] = []
    reasoning: list[str] = []
    calls: list[ToolCall] = []
    for block in response.content:
        if block.type == "text":
            texts.append(block.text)
        elif block.type == "thinking" and block.thinking:
            reasoning.append(block.thinking)
        elif block.type == "tool_use":
            calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
    return AssistantTurn(
        stop=_STOP_REASONS.get(response.stop_reason, "end"),
        text="\n".join(texts),
        tool_calls=tuple(calls),
        reasoning="\n".join(reasoning),
        model=response.model,
        raw=_ClaudeContent(tuple(response.content)),
    )
