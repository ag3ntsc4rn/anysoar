import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from anysoar.drivers.mock import MockDriver
from anysoar.errors import DenialReason, PolicyDeniedError
from anysoar.interface import ActionTier, Capability
from anysoar.mcp.cli import main
from anysoar.models import Note
from anysoar.policy import (
    Action,
    ApprovalUnavailableError,
    AuditEventKind,
    GuardedDriver,
    HttpApprover,
    MemoryAuditLog,
    audit_actor,
)

TOKEN = "submit-token"


@dataclass
class Service:
    """An approval service: decisions are set by the test."""

    decision: dict[str, Any] | None = None
    pending_polls: int = 1
    requests: list[dict[str, Any]] = field(default_factory=list)
    polls: int = 0
    expired: list[str] = field(default_factory=list)
    url: str = ""


@pytest.fixture
def service() -> Iterator[Service]:
    state = Service()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def reply(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def authorized(self) -> bool:
            if self.headers.get("Authorization") == f"Bearer {TOKEN}":
                return True
            self.reply(401, {"error": "bad token"})
            return False

        def do_POST(self) -> None:
            if not self.authorized():
                return
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/approvals":
                state.requests.append(body)
                self.reply(201, {"id": "a-1"})
            elif self.path.endswith("/expire"):
                state.expired.append(self.path.split("/")[3])
                self.reply(200, {"status": "expired"})

        def do_GET(self) -> None:
            if not self.authorized():
                return
            state.polls += 1
            if state.decision is None or state.polls <= state.pending_polls:
                self.reply(200, {"status": "pending", "approver": None, "reason": None})
            else:
                self.reply(200, state.decision)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


ACTION = Action(
    capability=Capability.CLOSE_CASE,
    tier=ActionTier.WRITE,
    summary="Close case case-0002 as benign",
    arguments={"case_uid": "case-0002", "verdict": "benign"},
)


def approver(service: Service, token: str = TOKEN) -> HttpApprover:
    return HttpApprover(service.url, token, poll_wait=0.05)


async def test_approved_after_waiting(service: Service) -> None:
    service.decision = {"status": "approved", "approver": "analyst1", "reason": "looks right"}
    token = audit_actor.set("mcp:triage-agent")
    try:
        approval = await approver(service).request_approval(ACTION)
    finally:
        audit_actor.reset(token)
    assert (approval.approved, approval.approver, approval.reason) == (
        True,
        "analyst1",
        "looks right",
    )
    (request,) = service.requests
    assert request["actor"] == "mcp:triage-agent"
    assert request["action"]["summary"] == "Close case case-0002 as benign"
    assert request["action"]["capability"] == "close_case"
    assert service.polls == 2  # one pending answer, then the decision


async def test_rejected(service: Service) -> None:
    service.decision = {"status": "rejected", "approver": "analyst1", "reason": "wrong case"}
    approval = await approver(service).request_approval(ACTION)
    assert not approval.approved
    assert approval.reason == "wrong case"


async def test_bad_token_means_no_approval(service: Service) -> None:
    with pytest.raises(ApprovalUnavailableError, match="rejected the token"):
        await approver(service, token="nope").request_approval(ACTION)


async def test_unreachable_service() -> None:
    unreachable = HttpApprover("http://127.0.0.1:9", TOKEN, poll_wait=0.05)
    with pytest.raises(ApprovalUnavailableError, match="unreachable"):
        await unreachable.request_approval(ACTION)


async def test_unexpected_status(service: Service) -> None:
    service.decision = {"status": "expired"}
    with pytest.raises(ApprovalUnavailableError, match="'expired'"):
        await approver(service).request_approval(ACTION)


async def test_through_the_guard(service: Service) -> None:
    service.decision = {"status": "approved", "approver": "analyst1", "reason": None}
    mock, log = MockDriver(), MemoryAuditLog()
    soar = GuardedDriver(mock, approver=approver(service), audit_log=log)
    await soar.add_note("case-0002", Note(comment="approved in the console"))
    assert (await mock.get_case("case-0002")).notes[-1].comment == "approved in the console"
    (approval,) = [e for e in log.events if e.kind is AuditEventKind.APPROVAL]
    assert approval.approval is not None
    assert approval.approval.approver == "analyst1"


async def test_timeout_expires_the_request_and_denies(service: Service) -> None:
    mock = MockDriver()
    soar = GuardedDriver(mock, approver=approver(service), approval_timeout=0.3)
    with pytest.raises(PolicyDeniedError) as denied:
        await soar.add_note("case-0002", Note(comment="never decided"))
    assert denied.value.reason is DenialReason.APPROVAL_TIMEOUT
    assert service.expired == ["a-1"]
    assert all(n.comment != "never decided" for n in (await mock.get_case("case-0002")).notes)


def test_cli_needs_url_and_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANYSOAR_APPROVAL_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="needs --approval-url and ANYSOAR_APPROVAL_TOKEN"):
        main(["--approver", "http", "--approval-url", "http://127.0.0.1:8765"])
