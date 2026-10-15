"""A scripted model for tests and offline demos: replays prepared turns, calls no LLM."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from anysoar_agent.model import AssistantTurn, ToolSpec, Transcript

__all__ = ["ModelRequest", "ScriptedModel"]


@dataclass(frozen=True)
class ModelRequest:
    """What the scripted model was asked, for assertions."""

    system: str
    transcript: tuple[object, ...]
    tools: tuple[ToolSpec, ...]


Step = AssistantTurn | Callable[[Transcript], AssistantTurn]


class ScriptedModel:
    """Returns the given turns in order. A step may be a function of the transcript so far,
    e.g. to use a uid returned by an earlier tool call."""

    def __init__(self, steps: Iterable[Step]) -> None:
        self._steps = list(steps)
        self.requests: list[ModelRequest] = []

    @property
    def name(self) -> str:
        return "scripted"

    async def respond(
        self, system: str, transcript: Transcript, tools: Sequence[ToolSpec]
    ) -> AssistantTurn:
        self.requests.append(ModelRequest(system, tuple(transcript), tuple(tools)))
        if not self._steps:
            raise RuntimeError("scripted model has no more turns")
        step = self._steps.pop(0)
        return step(transcript) if callable(step) else step
