"""The ``anysoar-agent`` command: triage a phishing case through anysoar's MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, TextIO

from mcp import Client, StdioServerParameters
from mcp.client import ClientRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitRequestParams, ElicitResult, Implementation

from anysoar_agent.agent import Agent, AgentEvent, AgentResult
from anysoar_agent.model import Model
from anysoar_agent.toolbox import McpToolbox
from anysoar_agent.triage import DEMO_CASE, SYSTEM_PROMPT, demo_model, task

__all__ = ["Approver", "main", "run_triage", "terminal_approver"]

Approver = Callable[[str], Awaitable[tuple[bool, str]]]
"""Shows an approval question to a human and returns (approved, reason)."""


def terminal_approver(
    read: Callable[[str], str] = input, out: TextIO = sys.stderr, interactive: bool | None = None
) -> Approver:
    """Ask the person at the terminal. Without an interactive terminal, decline."""

    async def ask(question: str) -> tuple[bool, str]:
        print(f"\n=== Approval needed ===\n{question}", file=out, flush=True)
        if not (sys.stdin.isatty() if interactive is None else interactive):
            print("(no interactive terminal: declined)", file=out, flush=True)
            return False, "no interactive terminal"
        try:
            answer = await asyncio.to_thread(read, "Approve? [y/N] ")
            approved = answer.strip().lower() in {"y", "yes"}
            reason = await asyncio.to_thread(read, "Reason (optional): ")
        except EOFError:
            print("(end of input: declined)", file=out, flush=True)
            return False, "no answer (end of input)"
        return approved, reason.strip()

    return ask


def _elicitation_callback(approver: Approver) -> Any:
    async def on_elicit(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
        approved, reason = await approver(params.message)
        return ElicitResult(action="accept", content={"approve": approved, "reason": reason})

    return on_elicit


def event_printer(out: TextIO = sys.stderr) -> Callable[[AgentEvent], None]:
    """Show what the agent is doing, one line per event."""

    def show(event: AgentEvent) -> None:
        if event.kind == "reasoning":
            print(f"  (thinking) {event.text}", file=out)
        elif event.kind == "text":
            print(f"  {event.text}", file=out)
        elif event.kind == "tool_call" and event.call is not None:
            args = json.dumps(event.call.arguments, separators=(",", ":"))
            print(f"-> {event.call.name} {args}", file=out)
        elif event.kind == "tool_result" and event.result is not None:
            if event.result.is_error:
                print(f"   x {event.result.content}", file=out)
            else:
                print(f"   ok ({len(event.result.content)} bytes)", file=out)
        out.flush()

    return show


async def run_triage(
    case_uid: str,
    model: Model,
    server: StdioServerParameters | MCPServer[Any],
    approver: Approver,
    *,
    max_turns: int = 40,
    on_event: Callable[[AgentEvent], Any] | None = None,
) -> AgentResult:
    """Connect to the MCP server and let the agent triage ``case_uid``."""
    async with Client(
        server,
        elicitation_callback=_elicitation_callback(approver),
        # Names the agent in the server's audit log (actor "mcp:anysoar-agent").
        client_info=Implementation(name="anysoar-agent", version="0.0.0"),
    ) as client:
        agent = Agent(
            model, McpToolbox(client), system=SYSTEM_PROMPT, max_turns=max_turns, on_event=on_event
        )
        return await agent.run(task(case_uid))


def _model(args: argparse.Namespace) -> Model:
    if args.provider == "demo":
        if args.case_uid != DEMO_CASE:
            sys.exit(f"anysoar-agent: the demo provider only knows {DEMO_CASE}")
        return demo_model()
    try:
        from anysoar_agent.claude import DEFAULT_MODEL, ClaudeModel
    except ImportError:
        sys.exit('anysoar-agent: the claude provider needs "anysoar-agent[claude]"')
    return ClaudeModel(args.model or DEFAULT_MODEL, effort=args.effort)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anysoar-agent",
        description="Reference AI agent for anysoar. Write actions ask for your approval.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    triage = commands.add_parser("triage", help="triage a phishing case")
    triage.add_argument("case_uid", help="the case to triage, e.g. case-0001")
    triage.add_argument(
        "--provider",
        choices=["claude", "demo"],
        default="claude",
        help="LLM provider; 'demo' replays a scripted triage of case-0002 offline "
        "(default: %(default)s)",
    )
    triage.add_argument("--model", help="model id for the provider (default: provider's)")
    triage.add_argument(
        "--effort", choices=["low", "medium", "high", "xhigh", "max"], default="high"
    )
    triage.add_argument("--max-turns", type=int, default=40)
    triage.add_argument(
        "--server-arg",
        action="append",
        default=[],
        metavar="ARG",
        help="extra argument for anysoar-mcp, e.g. --server-arg=--policy=policy.toml",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    model = _model(args)
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "anysoar.mcp", *args.server_arg],
        env=dict(os.environ),
    )
    print(f"anysoar-agent: {model.name} triaging {args.case_uid}", file=sys.stderr)
    result = asyncio.run(
        run_triage(
            args.case_uid,
            model,
            server,
            terminal_approver(),
            max_turns=args.max_turns,
            on_event=event_printer(),
        )
    )
    print(result.text)
    if result.stop != "end":
        sys.exit(f"anysoar-agent: stopped early ({result.stop})")
