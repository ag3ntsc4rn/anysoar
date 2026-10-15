import contextlib
import typing
from collections.abc import AsyncIterator
from typing import Any

import pytest
from mcp import Client
from mcp.client import ClientRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, ElicitRequestParams, ElicitResult

from anysoar.drivers.mock import MockDriver
from anysoar.interface import Capability
from anysoar.mcp import ElicitationApprover, create_server
from anysoar.mcp.server import AlertStatus, IndicatorType, Severity, Verdict
from anysoar.models import (
    DetectionFindingStatusId,
    IncidentFindingStatusId,
    ObservableTypeId,
    SeverityId,
    VerdictId,
)
from anysoar.policy import (
    ApproveAll,
    AuditEventKind,
    Decision,
    GuardedDriver,
    KillSwitch,
    MemoryAuditLog,
    Policy,
)


class User:
    """Stands in for the human answering approval prompts in the MCP client."""

    def __init__(self, action: str = "accept", approve: bool = True, reason: str = "") -> None:
        self.action = action
        self.content = {"approve": approve, "reason": reason}
        self.asked: list[str] = []

    async def __call__(
        self, context: ClientRequestContext, params: ElicitRequestParams
    ) -> ElicitResult:
        self.asked.append(params.message)
        content = self.content if self.action == "accept" else None
        return ElicitResult(action=self.action, content=content)  # type: ignore[arg-type]


class Harness:
    def __init__(self) -> None:
        self.mock = MockDriver()
        self.log = MemoryAuditLog()
        self.switch = KillSwitch()

    def guard(self, **kwargs: Any) -> GuardedDriver:
        kwargs.setdefault("approver", ElicitationApprover())
        return GuardedDriver(self.mock, audit_log=self.log, kill_switch=self.switch, **kwargs)

    async def server(self, **kwargs: Any) -> MCPServer[Any]:
        return await create_server(self.guard(**kwargs))

    @contextlib.asynccontextmanager
    async def connect(
        self, user: User | None = None, mode: str = "auto", **kwargs: Any
    ) -> AsyncIterator[Client]:
        """Open the client inside the test's own task (anyio scopes must not span tasks)."""
        server = await self.server(**kwargs)
        async with Client(server, mode=mode, elicitation_callback=user) as client:
            yield client


@pytest.fixture
def h() -> Harness:
    return Harness()


@pytest.fixture
def user() -> User:
    return User()


def text(result: CallToolResult) -> str:
    first = result.content[0]
    return first.text if first.type == "text" else ""


def data(result: CallToolResult) -> dict[str, Any]:
    assert not result.is_error, text(result)
    content: dict[str, Any] | None = result.structured_content
    assert content is not None
    return content


class TestTools:
    async def test_one_tool_per_capability(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert set(tools) == {"describe_soar"} | {c.value for c in Capability}
            for tool in tools.values():
                assert "approval" not in tool.input_schema.get("properties", {})
                assert tool.output_schema is not None
            assert tools["get_alert"].annotations is not None
            assert tools["get_alert"].annotations.read_only_hint is True
            assert tools["run_playbook"].annotations is not None
            assert tools["run_playbook"].annotations.destructive_hint is True

    async def test_denied_capabilities_are_not_offered(self, h: Harness) -> None:
        policy = Policy(capabilities={Capability.CLOSE_CASE: Decision.DENY})
        async with h.connect(policy=policy) as client:
            names = {t.name for t in (await client.list_tools()).tools}
        assert "close_case" not in names
        assert "add_note" in names

    async def test_describe_soar(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            info = data(await client.call_tool("describe_soar", {}))
            assert info["driver"] == "mock"
            assert info["kill_switch"] == {"engaged": False, "reason": None}
            policies = {op["tool"]: op["policy"] for op in info["operations"]}
            assert policies["get_alert"] == "allow"
            assert policies["close_case"] == "require_approval"

    async def test_list_alerts_filters_and_pages(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            first = data(
                await client.call_tool(
                    "list_alerts", {"status": ["new"], "min_severity": "medium", "limit": 2}
                )
            )
            assert [a["finding_info"]["uid"] for a in first["alerts"]] == [
                "alert-0008",
                "alert-0005",
            ]
            rest = data(
                await client.call_tool(
                    "list_alerts",
                    {"status": ["new"], "min_severity": "medium", "cursor": first["next_cursor"]},
                )
            )
            assert [a["finding_info"]["uid"] for a in rest["alerts"]] == ["alert-0003"]
            window = data(
                await client.call_tool(
                    "list_alerts", {"since": "2026-10-15T08:00:00Z", "until": "2026-10-15T08:01:00"}
                )
            )
            assert [a["finding_info"]["uid"] for a in window["alerts"]] == ["alert-0001"]

    async def test_reads_do_not_ask(self, user: User, h: Harness) -> None:
        async with h.connect(user) as client:
            alert = data(await client.call_tool("get_alert", {"alert_uid": "alert-0001"}))
            assert alert["class_uid"] == 2004
            case = data(await client.call_tool("get_case", {"case_uid": "case-0001"}))
            assert case["metadata"]["uid"] == "case-0001"
            enriched = data(
                await client.call_tool(
                    "enrich_indicator", {"type": "ip_address", "value": "203.0.113.25"}
                )
            )
            assert enriched["observable"]["reputation"]["score_id"] == 9
            assert user.asked == []

    async def test_list_playbooks_shows_policy(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            result = data(await client.call_tool("list_playbooks", {}))
            policies = {p["uid"]: p["policy"] for p in result["playbooks"]}
            assert policies["pb-block-sender"] == "require_approval"
            assert policies["pb-disable-account"] == "deny"

    async def test_not_found_is_a_clear_tool_error(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            result = await client.call_tool("get_case", {"case_uid": "case-9999"})
            assert result.is_error
            assert "case 'case-9999' not found" in text(result)

    async def test_invalid_arguments_are_rejected(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            result = await client.call_tool(
                "close_case", {"case_uid": "case-0002", "verdict": "meh"}
            )
            assert result.is_error


class TestApprovals:
    async def test_approved_write(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            user.content["reason"] = "matches known supplier"
            case = data(
                await client.call_tool(
                    "close_case", {"case_uid": "case-0002", "verdict": "benign", "comment": "fine"}
                )
            )
            assert case["status_id"] == IncidentFindingStatusId.CLOSED
            (question,) = user.asked
            assert "write action" in question
            assert "Close case case-0002 as benign: 'fine'" in question
            approval = next(e for e in h.log.events if e.kind is AuditEventKind.APPROVAL)
            assert approval.approval is not None
            assert approval.approval.approved
            assert approval.approval.reason == "matches known supplier"
            assert approval.actor is not None
            assert approval.actor.startswith("mcp:")

    @pytest.mark.parametrize(
        ("answer", "detail"),
        [
            (User(action="decline"), "declined in the MCP client"),
            (User(action="cancel"), "cancelled in the MCP client"),
            (User(approve=False, reason="wrong case"), "wrong case"),
        ],
        ids=["decline", "cancel", "answer-no"],
    )
    async def test_rejected_write(self, h: Harness, answer: User, detail: str) -> None:
        async with h.connect(answer) as client:
            result = await client.call_tool("add_note", {"case_uid": "case-0002", "comment": "x"})
        assert result.is_error
        assert "Denied by anysoar policy (approval_rejected)" in text(result)
        assert detail in text(result)
        assert all(n.comment != "x" for n in (await h.mock.get_case("case-0002")).notes)

    async def test_client_without_elicitation(self, h: Harness) -> None:
        async with h.connect() as client:
            result = await client.call_tool("add_note", {"case_uid": "case-0002", "comment": "x"})
            assert result.is_error
            assert "approval_unavailable" in text(result)
            assert "no form elicitation" in text(result)
            # Reads still work.
            data(await client.call_tool("get_alert", {"alert_uid": "alert-0001"}))

    async def test_destructive_playbook_is_denied_without_asking(
        self, user: User, h: Harness
    ) -> None:
        async with h.connect(user) as client:
            result = await client.call_tool(
                "run_playbook",
                {"playbook_uid": "pb-disable-account", "inputs": {"user": "alice@example.com"}},
            )
            assert result.is_error
            assert "Denied by anysoar policy (policy)" in text(result)
            assert user.asked == []

    async def test_playbook_run_to_completion(self, user: User, h: Harness) -> None:
        async with h.connect(user) as client:
            run = data(
                await client.call_tool(
                    "run_playbook",
                    {
                        "playbook_uid": "pb-block-sender",
                        "case_uid": "case-0001",
                        "inputs": {"sender": "it-support@example.net"},
                    },
                )
            )
            assert run["status"] == "queued"
            assert (
                "Run playbook 'Block sender' (pb-block-sender) on case case-0001" in user.asked[0]
            )
            while run["status"] not in ("succeeded", "failed", "cancelled"):
                run = data(await client.call_tool("get_playbook_run", {"run_uid": run["uid"]}))
            assert run["status"] == "succeeded"
            assert len(user.asked) == 1

    async def test_kill_switch_blocks_without_asking(self, h: Harness, user: User) -> None:
        async with h.connect(user) as client:
            h.switch.engage("paused by on-call")
            for name, args in [
                ("get_alert", {"alert_uid": "alert-0001"}),
                ("add_note", {"case_uid": "case-0002", "comment": "x"}),
            ]:
                result = await client.call_tool(name, args)
                assert result.is_error
                assert "(kill_switch): paused by on-call" in text(result)
            assert user.asked == []
            info = data(await client.call_tool("describe_soar", {}))
            assert info["kill_switch"] == {"engaged": True, "reason": "paused by on-call"}

    async def test_out_of_band_approver_never_elicits(self, h: Harness, user: User) -> None:
        async with h.connect(user, approver=ApproveAll()) as client:
            data(await client.call_tool("add_note", {"case_uid": "case-0002", "comment": "x"}))
        assert user.asked == []

    async def test_policy_overrides_skip_the_question(self, h: Harness, user: User) -> None:
        policy = Policy(capabilities={Capability.ADD_NOTE: Decision.ALLOW})
        async with h.connect(user, policy=policy) as client:
            data(await client.call_tool("add_note", {"case_uid": "case-0002", "comment": "x"}))
        assert user.asked == []

    async def test_legacy_protocol(self, h: Harness, user: User) -> None:
        async with h.connect(user, mode="legacy") as client:
            data(await client.call_tool("add_note", {"case_uid": "case-0002", "comment": "x"}))
        assert len(user.asked) == 1


@pytest.mark.parametrize(
    ("literal", "enum"),
    [
        (Verdict, VerdictId),
        (AlertStatus, DetectionFindingStatusId),
        (Severity, SeverityId),
        (IndicatorType, ObservableTypeId),
    ],
)
def test_argument_names_map_to_ocsf_enums(literal: Any, enum: Any) -> None:
    for name in typing.get_args(literal):
        assert enum[name.upper()].name.lower() == name
