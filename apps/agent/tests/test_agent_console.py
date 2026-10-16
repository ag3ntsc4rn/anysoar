import json
from pathlib import Path

import httpx2
import pytest

from anysoar_agent import AgentEvent
from anysoar_agent.cli import main
from anysoar_agent.console import ConsoleReporter, read_connection
from anysoar_agent.model import ToolCall, ToolResult


def recorder() -> tuple[list[dict[str, object]], httpx2.MockTransport]:
    sent: list[dict[str, object]] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["Authorization"] == "Bearer submit"
        sent.append(json.loads(request.content))
        return httpx2.Response(202, json={"ok": True})

    return sent, httpx2.MockTransport(handle)


async def test_events_become_console_reports() -> None:
    sent, transport = recorder()
    reporter = ConsoleReporter("http://console.test", "submit", transport=transport)
    call = ToolCall("1", "add_note", {"case_uid": "c", "comment": "x"})
    await reporter(AgentEvent("reasoning", text="Looks spoofed."))
    await reporter(AgentEvent("tool_call", call=call))
    await reporter(AgentEvent("tool_result", call=call, result=ToolResult("1", "{...}")))
    await reporter(
        AgentEvent("tool_result", call=call, result=ToolResult("1", "Denied", is_error=True))
    )
    await reporter(AgentEvent("done", text="end"))
    await reporter.aclose()
    runs = {e.pop("run") for e in sent}
    assert len(runs) == 1
    assert sent == [
        {"kind": "reasoning", "text": "Looks spoofed."},
        {"kind": "tool_call", "tool": "add_note", "arguments": {"case_uid": "c", "comment": "x"}},
        {"kind": "tool_result", "tool": "add_note", "ok": True},
        {"kind": "tool_result", "tool": "add_note", "ok": False, "output": "Denied"},
        {"kind": "done", "text": "finished (end)"},
    ]


async def test_unreachable_console_warns_once(capsys: pytest.CaptureFixture[str]) -> None:
    def down(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused")

    reporter = ConsoleReporter("http://console.test", "t", transport=httpx2.MockTransport(down))
    for _ in range(3):
        await reporter(AgentEvent("text", text="still working"))
    assert capsys.readouterr().err.count("console unreachable") == 1


def test_read_connection(tmp_path: Path) -> None:
    path = tmp_path / "console.env"
    path.write_text(
        "# comment\nANYSOAR_APPROVAL_URL=http://127.0.0.1:8765\nANYSOAR_APPROVAL_TOKEN=abc\n"
    )
    assert read_connection(path) == ("http://127.0.0.1:8765", "abc")
    path.write_text("ANYSOAR_APPROVAL_URL=x\n")
    with pytest.raises(ValueError, match="ANYSOAR_APPROVAL_TOKEN"):
        read_connection(path)


def test_console_flag_needs_a_running_console(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    with pytest.raises(SystemExit, match="no console running"):
        main(["triage", "case-0002", "--provider", "demo", "--console"])
    monkeypatch.delenv("ANYSOAR_APPROVAL_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="needs ANYSOAR_APPROVAL_TOKEN"):
        main(["triage", "case-0002", "--provider", "demo", "--console", "http://127.0.0.1:1"])
