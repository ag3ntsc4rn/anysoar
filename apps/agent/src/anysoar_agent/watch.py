"""A long-running agent: triage each open case, then wait for more.

It keeps one MCP session open. Before each case it asks which SOAR is active and lists that
SOAR's open cases, so if the SOAR behind anysoar is switched while it runs, its next case
and its tools come from the new SOAR, without a restart.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from mcp import Client

from anysoar_agent.agent import Agent, AgentEvent, AgentResult
from anysoar_agent.model import Model
from anysoar_agent.toolbox import McpToolbox
from anysoar_agent.triage import SYSTEM_PROMPT, task

__all__ = ["Handled", "watch"]

logger = logging.getLogger(__name__)

OPEN_STATUSES = ("new", "in_progress")


@dataclass(frozen=True)
class Handled:
    soar: str
    case_uid: str
    result: AgentResult
    switched_to: str | None = None
    """The SOAR that became active while this case was in progress, if any. Calls made after
    the switch went to that SOAR, which may not have this case."""


CaseHook = Callable[[str, str, dict[str, Any]], Awaitable[None]]


async def _active_soar(client: Client) -> str:
    described = await client.call_tool("describe_soar", {})
    return str((described.structured_content or {}).get("driver", "unknown"))


async def _open_cases(client: Client, statuses: Sequence[str]) -> tuple[str, list[dict[str, Any]]]:
    """The active SOAR's name and its open cases, oldest first."""
    soar = await _active_soar(client)
    listing = await client.call_tool("list_cases", {"status": list(statuses), "limit": 100})
    if listing.is_error:
        text = (
            listing.content[0].text if listing.content and listing.content[0].type == "text" else ""
        )
        logger.warning("cannot list cases on %s: %s", soar, text)
        return soar, []
    cases: list[dict[str, Any]] = (listing.structured_content or {}).get("cases", [])
    return soar, list(reversed(cases))


async def watch(
    client: Client,
    model_for: Callable[[str], Model],
    *,
    statuses: Sequence[str] = OPEN_STATUSES,
    interval: float = 5.0,
    max_cases: int | None = None,
    max_turns: int = 40,
    on_event: Callable[[AgentEvent], Any] | None = None,
    on_case: CaseHook | None = None,
    on_done: Callable[[Handled], Awaitable[None]] | None = None,
) -> list[Handled]:
    """Triage open cases one at a time until ``max_cases`` are done (or forever).

    Each case is triaged once per SOAR (case ids differ between SOARs). Between cases the
    agent re-checks the active SOAR, so a switch takes effect at the next case. Every call
    goes to the SOAR active at that moment, so a switch *during* a case sends its remaining
    calls to the new SOAR, where they will likely fail; that case is reported with
    ``switched_to``.
    """
    toolbox = McpToolbox(client)
    seen: set[tuple[str, str]] = set()
    handled: list[Handled] = []
    while max_cases is None or len(handled) < max_cases:
        soar, cases = await _open_cases(client, statuses)
        todo = [c for c in cases if (soar, c["metadata"]["uid"]) not in seen]
        if not todo:
            await asyncio.sleep(interval)
            continue
        case = todo[0]
        uid = case["metadata"]["uid"]
        seen.add((soar, uid))
        if on_case is not None:
            await on_case(soar, uid, case)
        agent = Agent(
            model_for(uid), toolbox, system=SYSTEM_PROMPT, max_turns=max_turns, on_event=on_event
        )
        result = await agent.run(task(uid))
        after = await _active_soar(client)
        switched = after if after != soar else None
        if switched is not None:
            logger.warning(
                "the SOAR switched from %s to %s while %s was in progress", soar, after, uid
            )
        handled.append(Handled(soar, uid, result, switched))
        if on_done is not None:
            await on_done(handled[-1])
    return handled
