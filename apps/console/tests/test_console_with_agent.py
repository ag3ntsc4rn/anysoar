"""The whole loop: the agent triages, the console shows it, a person approves in the console."""

import asyncio
import contextlib

from anysoar.drivers.mock import MockDriver
from anysoar.mcp import create_server
from anysoar.models import IncidentFindingStatusId
from anysoar.policy import GuardedDriver
from anysoar_agent.cli import run_triage, terminal_approver
from anysoar_agent.console import ConsoleReporter
from anysoar_agent.triage import demo_model

from .console_harness import Console


async def test_agent_works_through_the_console(console: Console) -> None:
    mock = MockDriver()
    guard = GuardedDriver(mock, approver=console.approver())
    server = await create_server(guard)
    reporter = ConsoleReporter(console.url, console.config.submit_token)
    person = await console.person()
    approved: list[str] = []

    async def approve_whatever_appears() -> None:
        while True:
            for item in (await person.get("/ui/state")).json()["approvals"]:
                if item["status"] == "pending":
                    approved.append(item["action"]["capability"])
                    await person.post(
                        f"/ui/approvals/{item['id']}/decide", json={"decision": "approve"}
                    )
            await asyncio.sleep(0.05)

    supervisor = asyncio.create_task(approve_whatever_appears())
    try:
        result = await asyncio.wait_for(
            run_triage(
                "case-0002",
                demo_model(),
                server,
                terminal_approver(interactive=False),  # never asked: approvals go to the console
                on_event=reporter,
            ),
            timeout=60,
        )
    finally:
        supervisor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await supervisor
        await reporter.aclose()

    assert result.stop == "end"
    assert approved == ["add_note", "run_playbook", "close_case"]
    assert (await mock.get_case("case-0002")).status_id is IncidentFindingStatusId.CLOSED

    state = (await person.get("/ui/state")).json()
    kinds = [e["kind"] for e in state["agent"]]
    assert kinds.count("tool_call") == kinds.count("tool_result") == 10
    assert kinds[-1] == "done"
    assert all(a["status"] == "approved" for a in state["approvals"])
    assert {a["approver"] for a in state["approvals"]} == {"analyst1"}
