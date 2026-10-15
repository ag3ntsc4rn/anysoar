import os
from types import SimpleNamespace
from typing import Any, cast

import pytest
from anthropic import AsyncAnthropic, omit
from anthropic.types.beta import BetaMessage
from mcp import Client

from anysoar.drivers.mock import MockDriver
from anysoar.mcp import create_server
from anysoar.policy import GuardedDriver
from anysoar_agent import Agent, McpToolbox
from anysoar_agent.claude import ClaudeModel, to_messages
from anysoar_agent.model import (
    AssistantTurn,
    Entry,
    ToolCall,
    ToolResult,
    ToolResults,
    ToolSpec,
    UserMessage,
)


def message(
    *content: dict[str, Any], stop: str = "end_turn", model: str = "claude-opus-5-5"
) -> BetaMessage:
    return BetaMessage.model_validate(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": list(content),
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    )


def thinking(text: str) -> dict[str, Any]:
    return {"type": "thinking", "thinking": text, "signature": "sig"}


def tool_use(id: str, name: str, **input: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": id, "name": name, "input": input}


def text(value: str) -> dict[str, Any]:
    return {"type": "text", "text": value}


class FakeClient:
    """Stands in for AsyncAnthropic: returns prepared messages, records requests."""

    def __init__(self, *responses: BetaMessage) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> BetaMessage:
        self.requests.append(kwargs)
        return self.responses.pop(0)


def claude(*responses: BetaMessage, **kwargs: Any) -> tuple[ClaudeModel, FakeClient]:
    fake = FakeClient(*responses)
    return ClaudeModel(client=cast(AsyncAnthropic, fake), **kwargs), fake


TOOLS = [ToolSpec("get_case", "Get a case", {"type": "object", "properties": {}})]


async def test_request_shape() -> None:
    model, fake = claude(message(text("hi")))
    await model.respond("You triage phishing.", [UserMessage("go")], TOOLS)
    (request,) = fake.requests
    assert request["model"] == "claude-opus-5-5"
    assert request["system"] == "You triage phishing."
    assert request["messages"] == [{"role": "user", "content": "go"}]
    assert request["tools"] == [
        {"name": "get_case", "description": "Get a case", "input_schema": TOOLS[0].input_schema}
    ]
    assert request["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert request["output_config"] == {"effort": "high"}
    assert request["cache_control"] == {"type": "ephemeral"}
    assert request["betas"] == ["server-side-fallback-2026-07-01"]
    assert request["fallbacks"] == "default"
    assert model.name == "claude:claude-opus-5-5"


async def test_fallbacks_can_be_turned_off() -> None:
    model, fake = claude(message(text("hi")), fallbacks=False, effort="medium")
    await model.respond("", [UserMessage("go")], [])
    assert fake.requests[0]["betas"] is omit
    assert fake.requests[0]["fallbacks"] is omit
    assert fake.requests[0]["output_config"] == {"effort": "medium"}


async def test_response_mapping() -> None:
    model, _ = claude(
        message(
            thinking("The sender domain is a look-alike."),
            text("Checking the case."),
            tool_use("tu_1", "get_case", case_uid="case-0002"),
            stop="tool_use",
            model="claude-opus-4-8",  # a fallback model answered
        )
    )
    turn = await model.respond("", [UserMessage("go")], TOOLS)
    assert turn.stop == "tool_use"
    assert turn.text == "Checking the case."
    assert turn.reasoning == "The sender domain is a look-alike."
    assert turn.tool_calls == (ToolCall("tu_1", "get_case", {"case_uid": "case-0002"}),)
    assert turn.model == "claude-opus-4-8"


@pytest.mark.parametrize(
    ("stop_reason", "stop"),
    [("end_turn", "end"), ("max_tokens", "max_tokens"), ("refusal", "refusal")],
)
async def test_stop_reasons(stop_reason: str, stop: str) -> None:
    model, _ = claude(message(stop=stop_reason))
    assert (await model.respond("", [UserMessage("go")], [])).stop == stop


async def test_replays_its_own_content_unchanged() -> None:
    first = message(thinking("hmm"), tool_use("tu_1", "get_case", case_uid="c"), stop="tool_use")
    model, fake = claude(first, message(text("done")))
    turn = await model.respond("", [UserMessage("go")], TOOLS)
    transcript: list[Entry] = [UserMessage("go"), turn, ToolResults((ToolResult("tu_1", "{}"),))]
    await model.respond("", transcript, TOOLS)

    replayed = fake.requests[1]["messages"]
    assert replayed[1] == {"role": "assistant", "content": list(first.content)}
    assert replayed[1]["content"][0] is first.content[0]  # the thinking block, untouched
    assert replayed[2] == {
        "role": "user",
        "content": [
            {"type": "tool_result", "tool_use_id": "tu_1", "content": "{}", "is_error": False}
        ],
    }


def test_turns_from_other_providers_are_converted() -> None:
    foreign = AssistantTurn(
        stop="tool_use", text="Looking.", tool_calls=(ToolCall("x1", "get_case", {"a": 1}),)
    )
    assert to_messages([UserMessage("go"), foreign])[1] == {
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Looking."},
            {"type": "tool_use", "id": "x1", "name": "get_case", "input": {"a": 1}},
        ],
    }


async def test_agent_with_claude_backend_over_mcp() -> None:
    model, fake = claude(
        message(tool_use("tu_1", "get_case", case_uid="case-0002"), stop="tool_use"),
        message(text("case-0002 is an invoice lure.")),
    )
    server = await create_server(GuardedDriver(MockDriver()))
    async with Client(server) as client:
        result = await Agent(model, McpToolbox(client), system="sys").run("triage case-0002")

    assert result.text == "case-0002 is an invoice lure."
    tool_result = fake.requests[1]["messages"][2]["content"][0]
    assert tool_result["tool_use_id"] == "tu_1"
    assert '"uid":"case-0002"' in tool_result["content"]
    assert {t["name"] for t in fake.requests[0]["tools"]} >= {"get_case", "describe_soar"}


@pytest.mark.skipif(
    os.environ.get("ANYSOAR_LIVE_CLAUDE") != "1",
    reason="calls the Claude API (costs money); set ANYSOAR_LIVE_CLAUDE=1 to run",
)
async def test_live_claude() -> None:
    model = ClaudeModel(effort="low")
    turn = await model.respond(
        "Call get_case for case-0002, then stop.", [UserMessage("Start.")], TOOLS
    )
    assert turn.tool_calls
