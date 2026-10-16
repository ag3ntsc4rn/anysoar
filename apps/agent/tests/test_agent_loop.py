import json
from typing import Any

import pytest
from mcp import Client
from mcp.client import ClientRequestContext
from mcp.types import ElicitRequestParams, ElicitResult

from anysoar.drivers.mock import MockDriver
from anysoar.mcp import ElicitationApprover, create_server
from anysoar.models import IncidentFindingStatusId
from anysoar.policy import GuardedDriver
from anysoar_agent import Agent, AgentEvent, McpToolbox
from anysoar_agent.model import (
    AssistantTurn,
    ToolCall,
    ToolResult,
    ToolResults,
    ToolSpec,
    Transcript,
    Usage,
    UserMessage,
)
from anysoar_agent.scripted import ScriptedModel


def calls(*specs: tuple[str, dict[str, Any]]) -> AssistantTurn:
    return AssistantTurn(
        stop="tool_use",
        tool_calls=tuple(ToolCall(f"c{i}", name, args) for i, (name, args) in enumerate(specs)),
    )


def done(text: str) -> AssistantTurn:
    return AssistantTurn(stop="end", text=text)


class FakeToolbox:
    def __init__(self) -> None:
        self.called: list[ToolCall] = []

    async def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec("echo", "Echo", {"type": "object"}),
            ToolSpec("boom", "Fails", {}),
            ToolSpec("group", "Fails inside a task group", {}),
        ]

    async def call(self, call: ToolCall) -> ToolResult:
        self.called.append(call)
        if call.name == "boom":
            raise RuntimeError("tool crashed")
        if call.name == "group":
            raise ExceptionGroup("unhandled errors in a TaskGroup", [EOFError("stdin closed")])
        return ToolResult(call.id, json.dumps(call.arguments))


class TestLoop:
    async def test_runs_tools_until_the_model_is_done(self) -> None:
        model = ScriptedModel([calls(("echo", {"x": 1}), ("echo", {"x": 2})), done("all good")])
        events: list[AgentEvent] = []
        result = await Agent(model, FakeToolbox(), system="sys", on_event=events.append).run(
            "do it"
        )

        assert (result.text, result.stop, result.turns) == ("all good", "end", 2)
        assert [e.kind for e in events] == [
            "tool_call",
            "tool_result",
            "tool_call",
            "tool_result",
            "text",
            "done",
        ]
        second = model.requests[1]
        assert second.system == "sys"
        assert isinstance(second.transcript[0], UserMessage)
        results = second.transcript[2]
        assert isinstance(results, ToolResults)
        assert [r.content for r in results.results] == ['{"x": 1}', '{"x": 2}']

    async def test_tool_errors_go_back_to_the_model(self) -> None:
        model = ScriptedModel([calls(("boom", {}), ("nope", {}), ("group", {})), done("handled")])
        result = await Agent(model, FakeToolbox(), system="").run("x")
        results = result.transcript[2]
        assert isinstance(results, ToolResults)
        assert [(r.is_error, r.content) for r in results.results] == [
            (True, "RuntimeError: tool crashed"),
            (True, "unknown tool 'nope'"),
            (True, "EOFError: stdin closed"),
        ]
        assert result.stop == "end"

    async def test_max_turns(self) -> None:
        model = ScriptedModel([calls(("echo", {}))] * 3)
        result = await Agent(model, FakeToolbox(), system="", max_turns=3).run("x")
        assert (result.stop, result.turns) == ("max_turns", 3)

    @pytest.mark.parametrize("stop", ["refusal", "max_tokens"])
    async def test_abnormal_stops_end_the_run(self, stop: Any) -> None:
        model = ScriptedModel([AssistantTurn(stop=stop)])
        assert (await Agent(model, FakeToolbox(), system="").run("x")).stop == stop

    async def test_async_event_handler_and_reasoning(self) -> None:
        seen: list[str] = []

        async def handler(event: AgentEvent) -> None:
            seen.append(event.kind)

        model = ScriptedModel([AssistantTurn(stop="end", text="hi", reasoning="thinking")])
        await Agent(model, FakeToolbox(), system="", on_event=handler).run("x")
        assert seen == ["reasoning", "text", "done"]


async def approve(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
    return ElicitResult(action="accept", content={"approve": True, "reason": "lgtm"})


async def decline(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
    return ElicitResult(action="decline")


def note_uid_from_last_result(transcript: Transcript) -> AssistantTurn:
    last = transcript[-1]
    assert isinstance(last, ToolResults)
    note = json.loads(last.results[0].content)
    return done(f"added note {note['uid']}")


async def test_drives_the_mock_soar_over_mcp() -> None:
    mock = MockDriver()
    server = await create_server(GuardedDriver(mock, approver=ElicitationApprover()))
    model = ScriptedModel(
        [
            calls(("get_case", {"case_uid": "case-0002"})),
            calls(("add_note", {"case_uid": "case-0002", "comment": "Looks malicious."})),
            note_uid_from_last_result,
        ]
    )
    async with Client(server, elicitation_callback=approve) as client:
        toolbox = McpToolbox(client)
        assert {"get_case", "add_note", "close_case"} <= {t.name for t in await toolbox.tools()}
        result = await Agent(model, toolbox, system="").run("triage case-0002")

    assert result.text == "added note note-0001"
    case_result = result.transcript[2]
    assert isinstance(case_result, ToolResults)
    assert json.loads(case_result.results[0].content)["metadata"]["uid"] == "case-0002"
    assert (await mock.get_case("case-0002")).notes[-1].comment == "Looks malicious."


async def test_declined_approval_reaches_the_model_as_an_error() -> None:
    mock = MockDriver()
    server = await create_server(GuardedDriver(mock, approver=ElicitationApprover()))
    model = ScriptedModel(
        [calls(("close_case", {"case_uid": "case-0002", "verdict": "benign"})), done("ok")]
    )
    async with Client(server, elicitation_callback=decline) as client:
        result = await Agent(model, McpToolbox(client), system="").run("x")

    outcome = result.transcript[2]
    assert isinstance(outcome, ToolResults)
    (closed,) = outcome.results
    assert closed.is_error
    assert "approval_rejected" in closed.content
    assert (await mock.get_case("case-0002")).status_id is IncidentFindingStatusId.NEW


async def test_result_sums_usage() -> None:
    model = ScriptedModel(
        [
            AssistantTurn(
                stop="tool_use",
                tool_calls=(ToolCall("1", "echo", {}),),
                usage=Usage(100, 0, 10),
            ),
            AssistantTurn(stop="end", text="ok", usage=Usage(150, 90, 20)),
        ]
    )
    result = await Agent(model, FakeToolbox(), system="").run("x")
    assert result.usage == Usage(250, 90, 30)
