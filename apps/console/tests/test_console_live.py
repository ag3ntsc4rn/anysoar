import asyncio
import json
from pathlib import Path

import httpx2

from anysoar.drivers import SoarSwitch, SwitchableDriver
from anysoar.drivers.mock import MockDriver
from anysoar.errors import DenialReason, PolicyDeniedError
from anysoar.policy import GuardedDriver, KillSwitch
from anysoar_console.app import CSRF_HEADER
from anysoar_console.watch import audit_entry

from .console_harness import Console


async def wait_for(person: httpx2.AsyncClient, key: str, count: int) -> list[dict[str, object]]:
    for _ in range(150):
        items: list[dict[str, object]] = (await person.get("/ui/state")).json()[key]
        if len(items) >= count:
            return items
        await asyncio.sleep(0.05)
    raise AssertionError(f"expected {count} {key} items")


class TestAgentActivity:
    async def test_agent_reports_and_people_see_it(self, console: Console) -> None:
        async with console.submitter() as agent:
            for event in (
                {
                    "kind": "start",
                    "run": "r1",
                    "text": "Triage case-0002",
                    "case": "case-0002",
                    "soar": "mock",
                },
                {"kind": "reasoning", "run": "r1", "text": "Sender looks spoofed."},
                {
                    "kind": "tool_call",
                    "run": "r1",
                    "tool": "get_case",
                    "arguments": {"case_uid": "c"},
                },
                {
                    "kind": "tool_result",
                    "run": "r1",
                    "tool": "get_case",
                    "ok": False,
                    "output": "boom",
                },
            ):
                assert (await agent.post("/api/agent/events", json=event)).status_code == 202
        person = await console.person()
        feed = await wait_for(person, "agent", 4)
        assert [e["kind"] for e in feed] == ["start", "reasoning", "tool_call", "tool_result"]
        # The page's status line ("Working on case case-0002 on mock") reads these.
        assert (feed[0]["case"], feed[0]["soar"]) == ("case-0002", "mock")
        assert feed[2]["arguments"] == {"case_uid": "c"}
        assert (feed[3]["ok"], feed[3]["output"]) == (False, "boom")

    async def test_limits_and_validation(self, console: Console) -> None:
        async with console.submitter() as agent:
            unknown = await agent.post("/api/agent/events", json={"kind": "approve"})
            assert unknown.status_code == 400
            await agent.post("/api/agent/events", json={"kind": "text", "text": "x" * 50_000})
            await agent.post(
                "/api/agent/events",
                json={"kind": "tool_call", "tool": "t", "arguments": {"big": "y" * 10_000}},
            )
        person = await console.person()
        text, call = await wait_for(person, "agent", 2)
        assert len(str(text["text"])) == 20_000
        assert call["arguments"] == {"truncated": True}

    async def test_only_the_submit_token_can_report(self, console: Console) -> None:
        person = await console.person()
        response = await person.post("/api/agent/events", json={"kind": "text", "text": "hi"})
        assert response.status_code == 401


class TestAuditTrail:
    async def test_follows_the_log(self, console: Console) -> None:
        log = console.config.audit_log
        assert log is not None
        log.write_text(
            json.dumps({"kind": "requested", "capability": "get_case", "summary": "a"}) + "\n"
        )
        person = await console.person()
        await wait_for(person, "audit", 1)

        with log.open("a") as file:
            completed = {"kind": "completed", "capability": "get_case", "summary": "a"}
            file.write(json.dumps(completed | {"duration_ms": 4}) + "\n")
            file.write("not json\n")
            file.write('{"kind": "denied", "summ')  # half-written line waits
        events = await wait_for(person, "audit", 2)
        assert [e["kind"] for e in events] == ["requested", "completed"]

        with log.open("a") as file:
            file.write('ary": "b", "reason": "kill_switch"}\n')
        events = await wait_for(person, "audit", 3)
        assert events[-1] == {"kind": "denied", "summary": "b", "reason": "kill_switch"}

    async def test_truncated_log_starts_over(self, console: Console) -> None:
        log = console.config.audit_log
        assert log is not None
        log.write_text('{"kind": "requested", "summary": "first"}\n' * 3)
        person = await console.person()
        await wait_for(person, "audit", 3)
        log.write_text('{"kind": "requested", "summary": "after"}\n')
        events = await wait_for(person, "audit", 4)
        assert events[-1]["summary"] == "after"

    def test_entry_keeps_only_known_fields(self) -> None:
        entry = audit_entry(
            json.dumps(
                {
                    "kind": "approval",
                    "summary": "s",
                    "arguments": {"secret": "not shown"},
                    "approval": {"approved": True, "approver": "a", "reason": None, "x": 1},
                }
            )
        )
        assert entry == {
            "kind": "approval",
            "summary": "s",
            "approval": {"approved": True, "approver": "a", "reason": None},
        }
        assert audit_entry("[1, 2]") is None


class TestKillSwitch:
    async def test_stop_from_the_console_blocks_anysoar(self, console: Console) -> None:
        path = console.config.kill_switch
        assert path is not None
        soar = GuardedDriver(MockDriver(), kill_switch=KillSwitch(path))
        await soar.get_case("case-0001")

        person = await console.person()
        stopped = await person.post(
            "/ui/kill-switch", json={"engaged": True, "reason": "agent misbehaving"}
        )
        assert stopped.json() == {
            "available": True,
            "engaged": True,
            "reason": "agent misbehaving (analyst1)",
        }
        try:
            await soar.get_case("case-0001")
            raise AssertionError("the kill switch did not stop anysoar")
        except PolicyDeniedError as denied:
            assert denied.reason is DenialReason.KILL_SWITCH

        resumed = await person.post("/ui/kill-switch", json={"engaged": False})
        assert resumed.json()["engaged"] is False
        assert not path.exists()
        await soar.get_case("case-0001")

    async def test_reflects_changes_made_elsewhere(self, console: Console) -> None:
        path = console.config.kill_switch
        assert path is not None
        person = await console.person()
        assert (await person.get("/ui/state")).json()["kill_switch"]["engaged"] is False
        path.write_text("on-call stopped it\n")
        state = (await person.get("/ui/state")).json()["kill_switch"]
        assert state == {"available": True, "engaged": True, "reason": "on-call stopped it"}

    async def test_only_people_can_use_it(self, console: Console) -> None:
        async with console.submitter() as agent:
            response = await agent.post(
                "/ui/kill-switch", json={"engaged": False}, headers={CSRF_HEADER: "1"}
            )
            assert response.status_code == 401
        person = await console.person()
        del person.headers[CSRF_HEADER]
        response = await person.post("/ui/kill-switch", json={"engaged": True})
        assert response.status_code == 401
        path = console.config.kill_switch
        assert path is not None and not path.exists()


def test_paths_are_optional(tmp_path: Path) -> None:
    from starlette.testclient import TestClient

    from anysoar_console.app import ConsoleConfig, create_app

    config = ConsoleConfig()
    with TestClient(create_app(config), base_url="http://127.0.0.1") as client:
        client.get(f"/login?token={config.login_token}")
        state = client.get("/ui/state").json()
        assert state["kill_switch"] == {"available": False, "engaged": False, "reason": None}
        assert state["soar"] == {"available": False, "active": None, "choices": []}
        assert state["audit"] == []


class TestSoarSwitch:
    async def test_switch_from_the_console_moves_anysoar(self, console: Console) -> None:
        path = console.config.soar_switch
        assert path is not None
        soar = SwitchableDriver(
            {"mock": MockDriver(), "shuffle": MockDriver()},
            SoarSwitch(path, ["mock", "shuffle"], default="mock"),
        )
        person = await console.person()
        state = (await person.get("/ui/state")).json()["soar"]
        assert state == {"available": True, "active": "mock", "choices": ["mock", "shuffle"]}
        assert soar.switch.active == "mock"

        switched = await person.post("/ui/soar", json={"soar": "shuffle"})
        assert switched.json()["active"] == "shuffle"
        assert soar.switch.active == "shuffle"
        assert path.read_text() == "shuffle\n"

        assert (await person.post("/ui/soar", json={"soar": "tines"})).status_code == 400

    async def test_only_people_can_switch(self, console: Console) -> None:
        async with console.submitter() as agent:
            response = await agent.post(
                "/ui/soar", json={"soar": "shuffle"}, headers={CSRF_HEADER: "1"}
            )
            assert response.status_code == 401
        person = await console.person()
        del person.headers[CSRF_HEADER]
        assert (await person.post("/ui/soar", json={"soar": "shuffle"})).status_code == 401
        path = console.config.soar_switch
        assert path is not None and not path.exists()

    async def test_reflects_switches_made_elsewhere(self, console: Console) -> None:
        path = console.config.soar_switch
        assert path is not None
        path.write_text("shuffle\n")
        person = await console.person()
        assert (await person.get("/ui/state")).json()["soar"]["active"] == "shuffle"
