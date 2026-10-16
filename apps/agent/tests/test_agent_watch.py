import asyncio
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from anysoar.drivers import SoarSwitch, SwitchableDriver
from anysoar.drivers.mock import MockDriver
from anysoar.mcp import create_server
from anysoar.policy import ApproveAll, GuardedDriver, KillSwitch
from anysoar_agent.cli import main
from anysoar_agent.triage import generic_demo_model
from anysoar_agent.watch import watch


def two_soars(tmp_path: Path) -> tuple[SwitchableDriver, MockDriver, MockDriver]:
    first, second = MockDriver(), MockDriver()
    switch = SoarSwitch(tmp_path / "SOAR", ["first", "second"], default="first")
    return SwitchableDriver({"first": first, "second": second}, switch), first, second


async def test_triages_each_open_case_once(tmp_path: Path) -> None:
    soar, first, _ = two_soars(tmp_path)
    server = await create_server(GuardedDriver(soar, approver=ApproveAll()))
    async with Client(server) as client:
        handled = await watch(client, generic_demo_model, interval=0.01, max_cases=2)
    # The mock's open cases, least recently updated first.
    assert [(h.soar, h.case_uid) for h in handled] == [
        ("first", "case-0001"),
        ("first", "case-0002"),
    ]
    assert all(h.result.stop == "end" for h in handled)
    for uid in ("case-0001", "case-0002"):
        notes = (await first.get_case(uid)).notes
        assert "anysoar demo agent" in notes[-1].comment


async def test_follows_a_switch_between_cases(tmp_path: Path) -> None:
    soar, first, second = two_soars(tmp_path)
    server = await create_server(GuardedDriver(soar, approver=ApproveAll()), resync_interval=0.01)

    async def switch_after_first(soar_name: str, case_uid: str, case: dict[str, Any]) -> None:
        if soar_name == "first":
            soar.switch.set("second")

    async with Client(server) as client:
        handled = await watch(
            client, generic_demo_model, interval=0.01, max_cases=2, on_case=switch_after_first
        )
    # Switched as the first case started, so that triage already ran on the second SOAR:
    # its note landed on the second SOAR's case-0001, making it the most recently updated
    # there, so the next (least recently updated) case is the second SOAR's case-0002.
    assert [(h.soar, h.case_uid) for h in handled] == [
        ("first", "case-0001"),
        ("second", "case-0002"),
    ]

    def demo_notes(case_notes: list[str]) -> int:
        return sum("anysoar demo agent" in c for c in case_notes)

    for uid in ("case-0001", "case-0002"):
        assert demo_notes([n.comment for n in (await first.get_case(uid)).notes]) == 0
        assert demo_notes([n.comment for n in (await second.get_case(uid)).notes]) == 1


async def test_waits_while_the_kill_switch_is_on(tmp_path: Path) -> None:
    soar, _, _ = two_soars(tmp_path)
    stop = KillSwitch()
    stop.engage("paused")
    server = await create_server(GuardedDriver(soar, approver=ApproveAll(), kill_switch=stop))
    async with Client(server) as client:
        task = asyncio.create_task(watch(client, generic_demo_model, interval=0.02, max_cases=1))
        await asyncio.sleep(0.2)
        assert not task.done()
        stop.release()
        (handled,) = await asyncio.wait_for(task, 10)
    assert handled.case_uid == "case-0001"


def test_watch_needs_a_console_when_asked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    with pytest.raises(SystemExit, match="no console running"):
        main(["watch", "--provider", "demo", "--console"])
