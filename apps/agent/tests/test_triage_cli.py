import io
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from anysoar.drivers.mock import MockDriver
from anysoar.mcp import ElicitationApprover, create_server
from anysoar.models import IncidentFindingStatusId
from anysoar.policy import GuardedDriver
from anysoar_agent import AgentEvent
from anysoar_agent.cli import event_printer, main, run_triage, terminal_approver
from anysoar_agent.model import AssistantTurn, ToolCall, ToolResult, ToolResults
from anysoar_agent.scripted import ScriptedModel
from anysoar_agent.triage import SYSTEM_PROMPT, demo_model, task


class Answers:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


async def approve_all(question: str) -> tuple[bool, str]:
    return True, "ok"


class TestTerminalApprover:
    async def test_yes_with_reason(self) -> None:
        out = io.StringIO()
        ask = terminal_approver(read=Answers("y", "known lure"), out=out, interactive=True)
        assert await ask("Close case?") == (True, "known lure")
        assert "Approval needed" in out.getvalue()
        assert "Close case?" in out.getvalue()

    @pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
    async def test_anything_but_yes_declines(self, answer: str) -> None:
        ask = terminal_approver(read=Answers(answer, ""), out=io.StringIO(), interactive=True)
        assert (await ask("?"))[0] is False

    async def test_end_of_input_declines(self) -> None:
        ask = terminal_approver(read=Answers(), out=io.StringIO(), interactive=True)
        assert await ask("?") == (False, "no answer (end of input)")

    async def test_non_interactive_declines_without_reading(self) -> None:
        read = Answers("y")
        ask = terminal_approver(read=read, out=io.StringIO(), interactive=False)
        assert await ask("?") == (False, "no interactive terminal")
        assert read.prompts == []


def test_event_printer() -> None:
    out = io.StringIO()
    show = event_printer(out)
    call = ToolCall("1", "get_case", {"case_uid": "c"})
    show(AgentEvent("reasoning", text="hmm"))
    show(AgentEvent("tool_call", call=call))
    show(AgentEvent("tool_result", call=call, result=ToolResult("1", "nope", is_error=True)))
    assert out.getvalue().splitlines() == [
        "  (thinking) hmm",
        '-> get_case {"case_uid":"c"}',
        "   x nope",
    ]


def test_prompt_treats_soar_data_as_untrusted() -> None:
    assert "untrusted data" in SYSTEM_PROMPT
    assert task("case-0001") == "Triage case case-0001."


async def test_demo_triage_in_process() -> None:
    mock = MockDriver()
    server = await create_server(GuardedDriver(mock, approver=ElicitationApprover()))
    questions: list[str] = []

    async def approver(question: str) -> tuple[bool, str]:
        questions.append(question)
        return True, "demo"

    events: list[AgentEvent] = []
    result = await run_triage("case-0002", demo_model(), server, approver, on_event=events.append)

    assert result.stop == "end"
    assert "true positive" in result.text
    errors = [e.result for e in events if e.result is not None and e.result.is_error]
    assert errors == []
    assert len(questions) == 3  # note, playbook, close
    case = await mock.get_case("case-0002")
    assert case.status_id is IncidentFindingStatusId.CLOSED
    assert any("demo agent" in n.comment for n in case.notes)


async def test_declined_writes_leave_the_case_open() -> None:
    mock = MockDriver()
    server = await create_server(GuardedDriver(mock, approver=ElicitationApprover()))

    async def decline(question: str) -> tuple[bool, str]:
        return False, "not today"

    result = await run_triage("case-0002", demo_model(), server, decline)
    assert result.stop == "end"
    closed = [
        r
        for entry in result.transcript
        if isinstance(entry, ToolResults)
        for r in entry.results
        if r.is_error
    ]
    assert len(closed) == 3
    assert all("approval_rejected" in r.content for r in closed)
    assert (await mock.get_case("case-0002")).status_id is IncidentFindingStatusId.NEW


async def test_tool_exception_detail_reaches_the_model() -> None:
    model = ScriptedModel(
        [
            AssistantTurn(stop="tool_use", tool_calls=(ToolCall("1", "get_case", {}),)),
            AssistantTurn(stop="end", text="done"),
        ]
    )
    server = await create_server(GuardedDriver(MockDriver()))
    result = await run_triage("x", model, server, approve_all)
    outcome = result.transcript[2]
    assert isinstance(outcome, ToolResults)
    assert outcome.results[0].is_error  # missing case_uid: a validation error, not a crash


async def test_demo_over_stdio(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "anysoar.mcp", "--audit-log", str(audit), "--kill-switch", str(tmp_path / "S")],
        env=dict(os.environ),
    )
    result = await run_triage("case-0002", demo_model(), server, approve_all)
    assert result.stop == "end"
    approvals = [
        json.loads(line)
        for line in audit.read_text().splitlines()
        if json.loads(line)["kind"] == "approval"
    ]
    assert [a["capability"] for a in approvals] == ["add_note", "run_playbook", "close_case"]


def test_demo_provider_only_knows_its_case() -> None:
    with pytest.raises(SystemExit, match="only knows case-0002"):
        main(["triage", "case-0001", "--provider", "demo"])
