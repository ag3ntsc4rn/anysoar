import asyncio
import json
import os
import stat
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx2
import pytest
import uvicorn
from starlette.testclient import TestClient

from anysoar.drivers.mock import MockDriver
from anysoar.errors import DenialReason, PolicyDeniedError
from anysoar.models import Note
from anysoar.policy import AuditEventKind, GuardedDriver, HttpApprover, MemoryAuditLog
from anysoar_console.app import CSRF_HEADER, SESSION_COOKIE, ConsoleConfig, create_app
from anysoar_console.cli import write_connection_file


@dataclass
class Console:
    url: str
    config: ConsoleConfig

    def approver(self) -> HttpApprover:
        return HttpApprover(self.url, self.config.submit_token, poll_wait=0.2)

    def submitter(self) -> httpx2.AsyncClient:
        token = self.config.submit_token
        return httpx2.AsyncClient(base_url=self.url, headers={"Authorization": f"Bearer {token}"})

    async def person(self) -> httpx2.AsyncClient:
        """A signed-in browser."""
        client = httpx2.AsyncClient(base_url=self.url, headers={CSRF_HEADER: "1"})
        response = await client.get(f"/login?token={self.config.login_token}")
        assert response.status_code in (200, 303)
        assert client.cookies.get(SESSION_COOKIE)
        return client


@pytest.fixture
def console() -> Iterator[Console]:
    config = ConsoleConfig(operator="analyst1")
    server = uvicorn.Server(
        uvicorn.Config(create_app(config), host="127.0.0.1", port=0, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield Console(f"http://127.0.0.1:{port}", config)
    server.should_exit = True
    thread.join(timeout=5)


async def pending(person: httpx2.AsyncClient) -> list[dict[str, object]]:
    for _ in range(100):
        approvals = (await person.get("/ui/state")).json()["approvals"]
        waiting = [a for a in approvals if a["status"] == "pending"]
        if waiting:
            return waiting
        await asyncio.sleep(0.02)
    raise AssertionError("no approval arrived")


class TestApprovalFlow:
    async def test_approve_in_the_console(self, console: Console) -> None:
        mock, log = MockDriver(), MemoryAuditLog()
        soar = GuardedDriver(mock, approver=console.approver(), audit_log=log)
        write = asyncio.create_task(soar.add_note("case-0002", Note(comment="from the console")))

        person = await console.person()
        (request,) = await pending(person)
        assert request["action"]["summary"] == "Add a note to case case-0002: 'from the console'"  # type: ignore[index]
        decided = await person.post(
            f"/ui/approvals/{request['id']}/decide",
            json={"decision": "approve", "reason": "  checked  "},
        )
        assert decided.json()["status"] == "approved"

        await asyncio.wait_for(write, 5)
        assert (await mock.get_case("case-0002")).notes[-1].comment == "from the console"
        (approval,) = [e for e in log.events if e.kind is AuditEventKind.APPROVAL]
        assert approval.approval is not None
        assert (approval.approval.approver, approval.approval.reason) == ("analyst1", "checked")

    async def test_reject(self, console: Console) -> None:
        mock = MockDriver()
        soar = GuardedDriver(mock, approver=console.approver())
        write = asyncio.create_task(soar.add_note("case-0002", Note(comment="no")))
        person = await console.person()
        (request,) = await pending(person)
        await person.post(f"/ui/approvals/{request['id']}/decide", json={"decision": "reject"})
        with pytest.raises(PolicyDeniedError) as denied:
            await asyncio.wait_for(write, 5)
        assert denied.value.reason is DenialReason.APPROVAL_REJECTED
        assert all(n.comment != "no" for n in (await mock.get_case("case-0002")).notes)

    async def test_timeout_shows_as_expired(self, console: Console) -> None:
        soar = GuardedDriver(MockDriver(), approver=console.approver(), approval_timeout=0.5)
        with pytest.raises(PolicyDeniedError):
            await soar.add_note("case-0002", Note(comment="too slow"))
        person = await console.person()
        (approval,) = (await person.get("/ui/state")).json()["approvals"]
        assert approval["status"] == "expired"
        late = await person.post(
            f"/ui/approvals/{approval['id']}/decide", json={"decision": "approve"}
        )
        assert late.status_code == 409

    async def test_live_stream(self, console: Console) -> None:
        person = await console.person()
        events: list[dict[str, object]] = []

        async def listen() -> None:
            async with person.stream("GET", "/ui/stream") as response:
                async for line in response.aiter_lines():
                    if line.startswith("data:"):
                        events.append(json.loads(line.removeprefix("data:").strip()))
                        return

        listener = asyncio.create_task(listen())
        await asyncio.sleep(0.2)
        async with console.submitter() as anysoar:
            await anysoar.post("/api/approvals", json={"action": {"summary": "Close case X"}})
        await asyncio.wait_for(listener, 5)
        (event,) = events
        assert event["kind"] == "approval"
        assert event["data"]["action"]["summary"] == "Close case X"  # type: ignore[index]


class TestSecurity:
    async def test_submit_token_cannot_decide(self, console: Console) -> None:
        async with console.submitter() as anysoar:
            created = await anysoar.post("/api/approvals", json={"action": {"summary": "x"}})
            approval_id = created.json()["id"]
            for path in ("/ui/state", "/"):
                assert (await anysoar.get(path)).status_code == 401
            decide = await anysoar.post(
                f"/ui/approvals/{approval_id}/decide",
                json={"decision": "approve"},
                headers={CSRF_HEADER: "1"},
            )
            assert decide.status_code == 401
            status = await anysoar.get(f"/api/approvals/{approval_id}")
            assert status.json()["status"] == "pending"

    async def test_session_cannot_submit(self, console: Console) -> None:
        person = await console.person()
        response = await person.post("/api/approvals", json={"action": {"summary": "x"}})
        assert response.status_code == 401

    async def test_decisions_need_the_console_header(self, console: Console) -> None:
        async with console.submitter() as anysoar:
            created = await anysoar.post("/api/approvals", json={"action": {"summary": "x"}})
        person = await console.person()
        del person.headers[CSRF_HEADER]
        response = await person.post(
            f"/ui/approvals/{created.json()['id']}/decide", json={"decision": "approve"}
        )
        assert response.status_code == 401

    async def test_wrong_tokens(self, console: Console) -> None:
        async with httpx2.AsyncClient(base_url=console.url) as stranger:
            assert (await stranger.get("/login?token=guess")).status_code == 401
            assert (await stranger.get("/")).status_code == 401
            submit = await stranger.post(
                "/api/approvals",
                json={"action": {"summary": "x"}},
                headers={"Authorization": "Bearer guess"},
            )
            assert submit.status_code == 401

    async def test_rejects_other_host_names(self, console: Console) -> None:
        async with httpx2.AsyncClient(base_url=console.url) as client:
            response = await client.get("/", headers={"Host": "attacker.example"})
            assert response.status_code == 400

    async def test_input_validation(self, console: Console) -> None:
        async with console.submitter() as anysoar:
            bad = await anysoar.post("/api/approvals", json={"action": {"no": "summary"}})
            assert bad.status_code == 400
            assert (await anysoar.get("/api/approvals/unknown")).status_code == 404
        person = await console.person()
        bad_decision = await person.post("/ui/approvals/x/decide", json={"decision": "maybe"})
        assert bad_decision.status_code == 400


def test_connection_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "state" / "console.env"
    write_connection_file(path, "http://127.0.0.1:8765", "submit-token")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "ANYSOAR_APPROVAL_TOKEN=submit-token" in path.read_text()
    assert os.access(path, os.R_OK)


def test_shutdown_hook_runs_when_the_server_stops() -> None:
    calls: list[str] = []
    with TestClient(
        create_app(on_shutdown=lambda: calls.append("stopped")), base_url="http://127.0.0.1"
    ):
        assert calls == []
    assert calls == ["stopped"]
