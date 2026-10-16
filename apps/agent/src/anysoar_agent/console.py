"""Report the agent's activity to the anysoar console, and find the console to report to."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import httpx2

from anysoar.mcp.cli import state_dir
from anysoar_agent.agent import AgentEvent

__all__ = ["ConsoleReporter", "connection_file", "read_connection"]


def connection_file() -> Path:
    """Where anysoar-console writes its address and submit token."""
    return state_dir() / "console.env"


def read_connection(path: Path) -> tuple[str, str]:
    """The console's URL and submit token from its connection file."""
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    try:
        return values["ANYSOAR_APPROVAL_URL"], values["ANYSOAR_APPROVAL_TOKEN"]
    except KeyError as exc:
        raise ValueError(f"{path} has no {exc.args[0]}") from exc


class ConsoleReporter:
    """Sends agent events to the console's agent panel.

    The console is an observer: if it cannot be reached, the agent carries on and this
    warns once. Tool output is only sent for failed calls.
    """

    def __init__(
        self, url: str, token: str, *, transport: httpx2.AsyncBaseTransport | None = None
    ) -> None:
        self.run = uuid.uuid4().hex[:12]
        self._http = httpx2.AsyncClient(
            base_url=url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
            transport=transport,
        )
        self._warned = False

    async def report(self, kind: str, **fields: Any) -> None:
        payload = {
            "kind": kind,
            "run": self.run,
            **{k: v for k, v in fields.items() if v is not None},
        }
        try:
            response = await self._http.post("/api/agent/events", json=payload)
            response.raise_for_status()
        except httpx2.HTTPError as exc:
            if not self._warned:
                self._warned = True
                print(f"anysoar-agent: console unreachable ({exc}); continuing", file=sys.stderr)

    async def __call__(self, event: AgentEvent) -> None:
        if event.kind == "tool_call" and event.call is not None:
            await self.report("tool_call", tool=event.call.name, arguments=event.call.arguments)
        elif event.kind == "tool_result" and event.call is not None and event.result is not None:
            failed = event.result.is_error
            await self.report(
                "tool_result",
                tool=event.call.name,
                ok=not failed,
                output=event.result.content if failed else None,
            )
        elif event.kind == "done":
            await self.report("done", text=f"finished ({event.text})")
        else:
            await self.report(event.kind, text=event.text)

    async def aclose(self) -> None:
        await self._http.aclose()
