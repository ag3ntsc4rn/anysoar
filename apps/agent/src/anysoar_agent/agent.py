"""The agent loop: ask the model, run the tools it calls, repeat until it is done."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol

from anysoar_agent.model import (
    AssistantTurn,
    Entry,
    Model,
    ToolCall,
    ToolResult,
    ToolResults,
    ToolSpec,
    Usage,
    UserMessage,
)

__all__ = ["Agent", "AgentEvent", "AgentResult", "Toolbox"]


class Toolbox(Protocol):
    async def tools(self) -> list[ToolSpec]: ...

    async def call(self, call: ToolCall) -> ToolResult: ...


@dataclass(frozen=True)
class AgentEvent:
    """Something the agent did, for live display and logging."""

    kind: Literal["reasoning", "text", "tool_call", "tool_result", "done"]
    text: str = ""
    call: ToolCall | None = None
    result: ToolResult | None = None


@dataclass
class AgentResult:
    text: str
    """The model's final answer."""
    stop: Literal["end", "max_turns", "max_tokens", "refusal"]
    turns: int
    transcript: list[Entry] = field(default_factory=list)

    @property
    def usage(self) -> Usage:
        """Tokens used by every model turn of the run."""
        return sum(
            (e.usage for e in self.transcript if isinstance(e, AssistantTurn)), start=Usage()
        )


EventHandler = Callable[[AgentEvent], Awaitable[None] | None]


class Agent:
    """Runs one task to completion with a model and a toolbox.

    Tool calls in a turn run one after another, not concurrently, because a call may stop to
    ask a human for approval. A tool that is not offered, or that raises, comes back to the
    model as an error result instead of ending the run.
    """

    def __init__(
        self,
        model: Model,
        toolbox: Toolbox,
        *,
        system: str,
        max_turns: int = 40,
        on_event: EventHandler | None = None,
    ) -> None:
        self.model = model
        self.toolbox = toolbox
        self.system = system
        self.max_turns = max_turns
        self.on_event = on_event

    async def run(self, task: str) -> AgentResult:
        tools = await self.toolbox.tools()
        offered = {t.name for t in tools}
        transcript: list[Entry] = [UserMessage(task)]
        for turn_number in range(1, self.max_turns + 1):
            turn = await self.model.respond(self.system, transcript, tools)
            transcript.append(turn)
            await self._report_turn(turn)
            if turn.stop != "tool_use" or not turn.tool_calls:
                stop = "end" if turn.stop == "tool_use" else turn.stop
                return await self._finish(turn.text, stop, turn_number, transcript)
            results = [await self._call(call, offered) for call in turn.tool_calls]
            transcript.append(ToolResults(tuple(results)))
        return await self._finish("", "max_turns", self.max_turns, transcript)

    async def _call(self, call: ToolCall, offered: set[str]) -> ToolResult:
        await self._emit(AgentEvent("tool_call", call=call))
        if call.name not in offered:
            result = ToolResult(call.id, f"unknown tool {call.name!r}", is_error=True)
        else:
            try:
                result = await self.toolbox.call(call)
            except Exception as exc:
                cause = _innermost(exc)
                result = ToolResult(call.id, f"{type(cause).__name__}: {cause}", is_error=True)
        await self._emit(AgentEvent("tool_result", call=call, result=result))
        return result

    async def _report_turn(self, turn: AssistantTurn) -> None:
        if turn.reasoning:
            await self._emit(AgentEvent("reasoning", text=turn.reasoning))
        if turn.text:
            await self._emit(AgentEvent("text", text=turn.text))

    async def _finish(
        self,
        text: str,
        stop: Literal["end", "max_turns", "max_tokens", "refusal"],
        turns: int,
        transcript: list[Entry],
    ) -> AgentResult:
        await self._emit(AgentEvent("done", text=stop))
        return AgentResult(text=text, stop=stop, turns=turns, transcript=transcript)

    async def _emit(self, event: AgentEvent) -> None:
        if self.on_event is not None:
            outcome = self.on_event(event)
            if inspect.isawaitable(outcome):
                await outcome


def _innermost(exc: BaseException) -> BaseException:
    """The first leaf of an exception group (task groups wrap the real error)."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc
