from pathlib import Path

import pytest

from anysoar.drivers.mock import MockDriver
from anysoar.errors import DenialReason, PolicyDeniedError
from anysoar.models import Note
from anysoar.policy import (
    Action,
    Approval,
    ApproveAll,
    AuditEventKind,
    GuardedDriver,
    KillSwitch,
    MemoryAuditLog,
)


class EngagingApprover:
    """Approves, but the operator hits the kill switch while the approval is pending."""

    def __init__(self, switch: KillSwitch) -> None:
        self.switch = switch

    async def request_approval(self, action: Action) -> Approval:
        self.switch.engage("operator stopped the agent")
        return Approval(approved=True, approver="analyst1")


async def test_in_process_switch_blocks_everything() -> None:
    switch = KillSwitch()
    log = MemoryAuditLog()
    soar = GuardedDriver(MockDriver(), kill_switch=switch, audit_log=log)
    await soar.get_alert("alert-0001")

    switch.engage("suspicious agent behaviour")
    with pytest.raises(PolicyDeniedError, match="suspicious agent behaviour") as denied:
        await soar.get_alert("alert-0001")
    assert denied.value.reason is DenialReason.KILL_SWITCH
    assert log.events[-1].kind is AuditEventKind.DENIED
    assert log.events[-1].reason is DenialReason.KILL_SWITCH

    switch.release()
    await soar.get_alert("alert-0001")


async def test_file_switch(tmp_path: Path) -> None:
    stop = tmp_path / "STOP"
    switch = KillSwitch(stop)
    soar = GuardedDriver(MockDriver(), kill_switch=switch)
    assert not switch.engaged

    stop.touch()
    with pytest.raises(PolicyDeniedError, match="present"):
        await soar.list_playbooks()

    stop.write_text("incident 42: agent paused by on-call\nmore text\n")
    assert switch.reason == "incident 42: agent paused by on-call"
    switch.release()
    assert switch.engaged, "release() must not clear a file switch"

    stop.unlink()
    await soar.list_playbooks()


async def test_unreadable_switch_file_fails_closed(tmp_path: Path) -> None:
    stop = tmp_path / "STOP"
    stop.mkdir()
    assert KillSwitch(stop).engaged


async def test_rechecked_after_approval() -> None:
    switch = KillSwitch()
    mock = MockDriver()
    soar = GuardedDriver(mock, approver=EngagingApprover(switch), kill_switch=switch)
    with pytest.raises(PolicyDeniedError) as denied:
        await soar.add_note("case-0002", Note(comment="approved too late"))
    assert denied.value.reason is DenialReason.KILL_SWITCH
    assert all(n.comment != "approved too late" for n in (await mock.get_case("case-0002")).notes)


async def test_switch_overrides_auto_approval() -> None:
    switch = KillSwitch()
    switch.engage()
    soar = GuardedDriver(MockDriver(), approver=ApproveAll(), kill_switch=switch)
    with pytest.raises(PolicyDeniedError, match="engaged by operator"):
        await soar.add_note("case-0002", Note(comment="x"))
