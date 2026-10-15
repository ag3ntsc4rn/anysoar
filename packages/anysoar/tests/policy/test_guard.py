import asyncio

import pytest
from pydantic import JsonValue, ValidationError

from anysoar.drivers.mock import MockDriver
from anysoar.errors import (
    CapabilityNotSupportedError,
    DenialReason,
    NotFoundError,
    PolicyDeniedError,
)
from anysoar.interface import ActionTier, AlertQuery, Capability, Driver, Page, PlaybookRun
from anysoar.models import DetectionFinding, IncidentFindingStatusId, Note, VerdictId
from anysoar.policy import (
    Action,
    Approval,
    ApprovalUnavailableError,
    ApproveAll,
    Decision,
    GuardedDriver,
    Policy,
)
from anysoar.testing import DriverContract


class RecordingApprover:
    def __init__(self, approved: bool = True, reason: str | None = None) -> None:
        self.approved = approved
        self.reason = reason
        self.actions: list[Action] = []

    async def request_approval(self, action: Action) -> Approval:
        self.actions.append(action)
        return Approval(approved=self.approved, approver="analyst1", reason=self.reason)


class SlowApprover:
    async def request_approval(self, action: Action) -> Approval:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")


class UnavailableApprover:
    async def request_approval(self, action: Action) -> Approval:
        raise ApprovalUnavailableError("client cannot prompt the user")


class NoPlaybookListing(Driver):
    """Can run playbooks but cannot list them, so their tier is unknown."""

    name = "no-listing"

    def __init__(self) -> None:
        self.mock = MockDriver()

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: dict[str, JsonValue] | None = None,  # type: ignore[override]
    ) -> PlaybookRun:
        return await self.mock.run_playbook(playbook_uid)


class TestGuardedMockContract(DriverContract):
    """With every approval granted, a guarded driver behaves like the driver it wraps."""

    @pytest.fixture
    def driver(self) -> GuardedDriver:
        return GuardedDriver(MockDriver(), approver=ApproveAll())

    @pytest.fixture
    def case_uid(self) -> str:
        return "case-0002"

    @pytest.fixture
    def playbook_inputs(self) -> dict[str, JsonValue]:
        return {"sender": "billing@example.org"}


class TestPolicy:
    def test_defaults(self) -> None:
        policy = Policy()
        assert policy.decide_capability(Capability.GET_ALERT) is Decision.ALLOW
        assert policy.decide_capability(Capability.ADD_NOTE) is Decision.REQUIRE_APPROVAL
        assert policy.tiers[ActionTier.DESTRUCTIVE] is Decision.DENY

    def test_precedence(self) -> None:
        policy = Policy(
            capabilities={Capability.ADD_NOTE: Decision.ALLOW},
            playbooks={"pb-1": Decision.REQUIRE_APPROVAL},
        )

        def action(capability: Capability, tier: ActionTier, **arguments: JsonValue) -> Action:
            return Action(capability=capability, tier=tier, summary="x", arguments=arguments)

        assert policy.decide(action(Capability.ADD_NOTE, ActionTier.WRITE)) is Decision.ALLOW
        destructive = ActionTier.DESTRUCTIVE
        run = Capability.RUN_PLAYBOOK
        assert policy.decide(action(run, destructive, playbook_uid="pb-1")) is (
            Decision.REQUIRE_APPROVAL
        )
        assert policy.decide(action(run, destructive, playbook_uid="pb-2")) is Decision.DENY

    def test_every_tier_needs_a_decision(self) -> None:
        with pytest.raises(ValidationError, match="destructive"):
            Policy(tiers={ActionTier.READ: Decision.ALLOW, ActionTier.WRITE: Decision.ALLOW})

    def test_run_playbook_cannot_be_set_for_all_playbooks(self) -> None:
        with pytest.raises(ValidationError, match="per playbook"):
            Policy(capabilities={Capability.RUN_PLAYBOOK: Decision.ALLOW})

    def test_policy_is_immutable(self) -> None:
        with pytest.raises(ValidationError):
            Policy().tiers = {}  # type: ignore[misc]


class TestGuardedDriver:
    async def test_reads_need_no_approver(self) -> None:
        soar = GuardedDriver(MockDriver())
        assert (await soar.get_alert("alert-0001")).finding_info.uid == "alert-0001"
        assert soar.name == "mock"

    async def test_write_without_approver_is_denied_before_the_soar(self) -> None:
        mock = MockDriver()
        soar = GuardedDriver(mock)
        with pytest.raises(PolicyDeniedError) as denied:
            await soar.add_note("case-0002", Note(comment="hello"))
        assert denied.value.reason is DenialReason.APPROVAL_UNAVAILABLE
        assert denied.value.capability is Capability.ADD_NOTE
        assert all(n.comment != "hello" for n in (await mock.get_case("case-0002")).notes)

    async def test_approver_sees_a_readable_action(self) -> None:
        approver = RecordingApprover()
        soar = GuardedDriver(MockDriver(), approver=approver)
        await soar.close_case("case-0002", verdict_id=VerdictId.BENIGN, comment="Known supplier")
        (action,) = approver.actions
        assert action.capability is Capability.CLOSE_CASE
        assert action.tier is ActionTier.WRITE
        assert action.summary == "Close case case-0002 as benign: 'Known supplier'"
        assert action.arguments == {
            "case_uid": "case-0002",
            "verdict": "benign",
            "comment": "Known supplier",
        }

    async def test_rejection(self) -> None:
        mock = MockDriver()
        soar = GuardedDriver(mock, approver=RecordingApprover(approved=False, reason="not yet"))
        with pytest.raises(PolicyDeniedError, match="rejected by analyst1: not yet") as denied:
            await soar.close_case("case-0002", verdict_id=VerdictId.BENIGN)
        assert denied.value.reason is DenialReason.APPROVAL_REJECTED
        assert (await mock.get_case("case-0002")).status_id is IncidentFindingStatusId.NEW

    async def test_approval_timeout(self) -> None:
        soar = GuardedDriver(MockDriver(), approver=SlowApprover(), approval_timeout=0.01)
        with pytest.raises(PolicyDeniedError) as denied:
            await soar.add_note("case-0002", Note(comment="x"))
        assert denied.value.reason is DenialReason.APPROVAL_TIMEOUT

    async def test_approver_unavailable(self) -> None:
        soar = GuardedDriver(MockDriver(), approver=UnavailableApprover())
        with pytest.raises(PolicyDeniedError, match="cannot prompt") as denied:
            await soar.add_note("case-0002", Note(comment="x"))
        assert denied.value.reason is DenialReason.APPROVAL_UNAVAILABLE

    async def test_destructive_playbook_is_denied_without_asking(self) -> None:
        approver = RecordingApprover()
        soar = GuardedDriver(MockDriver(), approver=approver)
        with pytest.raises(PolicyDeniedError) as denied:
            await soar.run_playbook("pb-disable-account", inputs={"user": "alice@example.com"})
        assert denied.value.reason is DenialReason.POLICY
        assert approver.actions == []

    async def test_playbook_action(self) -> None:
        approver = RecordingApprover()
        soar = GuardedDriver(MockDriver(), approver=approver)
        await soar.run_playbook(
            "pb-block-sender", case_uid="case-0001", inputs={"sender": "it-support@example.net"}
        )
        (action,) = approver.actions
        assert action.summary == "Run playbook 'Block sender' (pb-block-sender) on case case-0001"
        assert action.playbook_uid == "pb-block-sender"

    async def test_overrides(self) -> None:
        policy = Policy(
            capabilities={Capability.ADD_NOTE: Decision.ALLOW},
            playbooks={"pb-notify-reporter": Decision.ALLOW},
        )
        soar = GuardedDriver(MockDriver(), policy=policy)
        await soar.add_note("case-0002", Note(comment="allowed without approval"))
        await soar.run_playbook("pb-notify-reporter")
        with pytest.raises(PolicyDeniedError):
            await soar.run_playbook("pb-block-url", inputs={"url": "https://share.example.net/"})

    async def test_reads_can_be_denied(self) -> None:
        policy = Policy(capabilities={Capability.LIST_ALERTS: Decision.DENY})
        soar = GuardedDriver(MockDriver(), policy=policy)
        with pytest.raises(PolicyDeniedError, match="read action denied by policy"):
            await soar.list_alerts(AlertQuery(limit=1))

    async def test_unknown_playbook_is_not_found_before_approval(self) -> None:
        approver = RecordingApprover()
        soar = GuardedDriver(MockDriver(), approver=approver)
        with pytest.raises(NotFoundError):
            await soar.run_playbook("pb-nope")
        assert approver.actions == []

    async def test_playbook_of_unknown_risk_is_destructive(self) -> None:
        approver = RecordingApprover()
        soar = GuardedDriver(NoPlaybookListing(), approver=approver)
        with pytest.raises(PolicyDeniedError) as denied:
            await soar.run_playbook("pb-notify-reporter")
        assert denied.value.reason is DenialReason.POLICY
        assert approver.actions == []

    async def test_unsupported_capability_is_reported_before_approval(self) -> None:
        approver = RecordingApprover()
        soar = GuardedDriver(NoPlaybookListing(), approver=approver)
        with pytest.raises(CapabilityNotSupportedError) as raised:
            await soar.add_note("case-0001", Note(comment="x"))
        assert raised.value.driver == "no-listing"
        assert approver.actions == []

    async def test_describe_hides_denied_capabilities(self) -> None:
        policy = Policy(
            tiers={
                ActionTier.READ: Decision.ALLOW,
                ActionTier.WRITE: Decision.DENY,
                ActionTier.DESTRUCTIVE: Decision.DENY,
            }
        )
        info = await GuardedDriver(MockDriver(), policy=policy).describe()
        assert info.name == "mock"
        assert Capability.ADD_NOTE not in info.capabilities
        assert Capability.CLOSE_CASE not in info.capabilities
        # Playbooks are judged one by one, so the capability stays.
        assert Capability.RUN_PLAYBOOK in info.capabilities

    async def test_aclose_closes_the_wrapped_driver(self) -> None:
        class Closing(MockDriver):
            closed = 0

            async def aclose(self) -> None:
                self.closed += 1

        inner = Closing()
        async with GuardedDriver(inner):
            pass
        assert inner.closed == 1

    async def test_list_alerts_passes_the_query_through(self) -> None:
        soar = GuardedDriver(MockDriver())
        page: Page[DetectionFinding] = await soar.list_alerts(AlertQuery(limit=2))
        assert len(page.items) == 2
