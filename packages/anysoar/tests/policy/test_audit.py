import json
import logging
import stat
from pathlib import Path

import pytest

from anysoar.drivers.mock import MockDriver
from anysoar.errors import DenialReason, NotFoundError, PolicyDeniedError
from anysoar.interface import ActionTier, Capability
from anysoar.models import Note, VerdictId
from anysoar.policy import (
    Action,
    Approval,
    ApproveAll,
    AuditEvent,
    AuditEventKind,
    Decision,
    GuardedDriver,
    JsonlAuditLog,
    MemoryAuditLog,
    audit_actor,
)

R, A, C, D, F = (
    AuditEventKind.REQUESTED,
    AuditEventKind.APPROVAL,
    AuditEventKind.COMPLETED,
    AuditEventKind.DENIED,
    AuditEventKind.FAILED,
)


class Rejecter:
    async def request_approval(self, action: Action) -> Approval:
        return Approval(approved=False, approver="analyst1", reason="not enough evidence")


class BrokenLog:
    """Fails on the n-th event (1-based)."""

    def __init__(self, fail_on: int) -> None:
        self.fail_on = fail_on
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> None:
        if len(self.events) + 1 == self.fail_on:
            raise OSError("disk full")
        self.events.append(event)

    async def aclose(self) -> None:
        pass


def kinds(log: MemoryAuditLog) -> list[AuditEventKind]:
    return [e.kind for e in log.events]


async def test_allowed_read() -> None:
    log = MemoryAuditLog()
    await GuardedDriver(MockDriver(), audit_log=log).get_alert("alert-0001")
    requested, completed = log.events
    assert (requested.kind, completed.kind) == (R, C)
    assert requested.call_uid == completed.call_uid
    assert requested.decision is Decision.ALLOW
    assert requested.arguments == {"alert_uid": "alert-0001"}
    assert (requested.driver, requested.capability) == ("mock", Capability.GET_ALERT)
    assert completed.duration_ms is not None
    assert completed.arguments is None


async def test_approved_write() -> None:
    log = MemoryAuditLog()
    soar = GuardedDriver(MockDriver(), approver=ApproveAll(), audit_log=log)
    note = await soar.add_note("case-0002", Note(comment="checked"))
    assert kinds(log) == [R, A, C]
    assert log.events[0].decision is Decision.REQUIRE_APPROVAL
    assert log.events[1].approval == Approval(
        approved=True, approver="auto", reason="ApproveAll approver"
    )
    assert log.events[2].result_ref == note.uid
    assert len({e.call_uid for e in log.events}) == 1


async def test_rejected_write() -> None:
    log = MemoryAuditLog()
    soar = GuardedDriver(MockDriver(), approver=Rejecter(), audit_log=log)
    with pytest.raises(PolicyDeniedError):
        await soar.close_case("case-0002", verdict_id=VerdictId.BENIGN)
    assert kinds(log) == [R, A, D]
    assert log.events[2].reason is DenialReason.APPROVAL_REJECTED
    assert log.events[2].detail == "rejected by analyst1: not enough evidence"


async def test_denied_by_policy_and_without_approver() -> None:
    log = MemoryAuditLog()
    soar = GuardedDriver(MockDriver(), audit_log=log)
    with pytest.raises(PolicyDeniedError):
        await soar.run_playbook("pb-disable-account", inputs={"user": "alice@example.com"})
    with pytest.raises(PolicyDeniedError):
        await soar.add_note("case-0002", Note(comment="x"))
    assert kinds(log) == [R, D, R, D]
    assert log.events[0].tier is ActionTier.DESTRUCTIVE
    assert log.events[0].decision is Decision.DENY
    assert log.events[1].reason is DenialReason.POLICY
    assert log.events[3].reason is DenialReason.APPROVAL_UNAVAILABLE


async def test_driver_failure() -> None:
    log = MemoryAuditLog()
    with pytest.raises(NotFoundError):
        await GuardedDriver(MockDriver(), audit_log=log).get_case("case-9999")
    assert kinds(log) == [R, F]
    assert log.events[1].error_type == "NotFoundError"
    assert log.events[1].detail == "case 'case-9999' not found"


async def test_records_the_actor() -> None:
    log = MemoryAuditLog()
    soar = GuardedDriver(MockDriver(), audit_log=log)
    token = audit_actor.set("mcp:triage-agent")
    try:
        await soar.list_playbooks()
    finally:
        audit_actor.reset(token)
    await soar.list_playbooks()
    assert [e.actor for e in log.events] == ["mcp:triage-agent"] * 2 + [None] * 2


async def test_unrecordable_action_is_not_run() -> None:
    mock = MockDriver()
    soar = GuardedDriver(mock, approver=ApproveAll(), audit_log=BrokenLog(fail_on=1))
    with pytest.raises(PolicyDeniedError, match="disk full") as denied:
        await soar.add_note("case-0002", Note(comment="unrecorded"))
    assert denied.value.reason is DenialReason.AUDIT_UNAVAILABLE
    assert all(n.comment != "unrecorded" for n in (await mock.get_case("case-0002")).notes)


async def test_unrecordable_approval_is_not_run() -> None:
    mock = MockDriver()
    soar = GuardedDriver(mock, approver=ApproveAll(), audit_log=BrokenLog(fail_on=2))
    with pytest.raises(PolicyDeniedError) as denied:
        await soar.add_note("case-0002", Note(comment="unrecorded"))
    assert denied.value.reason is DenialReason.AUDIT_UNAVAILABLE
    assert all(n.comment != "unrecorded" for n in (await mock.get_case("case-0002")).notes)


async def test_unrecordable_outcome_still_returns(caplog: pytest.LogCaptureFixture) -> None:
    soar = GuardedDriver(MockDriver(), audit_log=BrokenLog(fail_on=2))
    with caplog.at_level(logging.ERROR, logger="anysoar.policy.guard"):
        alert = await soar.get_alert("alert-0001")
    assert alert.finding_info.uid == "alert-0001"
    assert "could not write completed audit event" in caplog.text


async def test_jsonl_log(tmp_path: Path) -> None:
    path = tmp_path / "state" / "audit.jsonl"
    async with GuardedDriver(MockDriver(), audit_log=JsonlAuditLog(path)) as soar:
        await soar.get_alert("alert-0001")
    async with GuardedDriver(MockDriver(), audit_log=JsonlAuditLog(path)) as soar:
        await soar.list_playbooks()
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [line["kind"] for line in lines] == ["requested", "completed"] * 2
    assert lines[0]["capability"] == "get_alert"
    assert "approval" not in lines[0]
    assert [AuditEvent.model_validate(line).kind for line in lines] == [R, C, R, C]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
