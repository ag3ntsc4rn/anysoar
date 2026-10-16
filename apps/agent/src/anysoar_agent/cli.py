"""The ``anysoar-agent`` command: triage a phishing case through anysoar's MCP server."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, TextIO

from mcp import Client, StdioServerParameters
from mcp.client import ClientRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitRequestParams, ElicitResult, Implementation

from anysoar_agent.agent import Agent, AgentEvent, AgentResult
from anysoar_agent.console import ConsoleReporter, connection_file, read_connection
from anysoar_agent.model import Model
from anysoar_agent.toolbox import McpToolbox
from anysoar_agent.triage import DEMO_CASE, SYSTEM_PROMPT, demo_model, generic_demo_model, task
from anysoar_agent.watch import OPEN_STATUSES, Handled, watch

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
            print(_indent(event.text, "  (thinking) "), file=out)
        elif event.kind == "text":
            print(_indent(event.text, "  "), file=out)
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


def _indent(text: str, first: str) -> str:
    """Indent ``text`` under a prefix, dropping blank lines."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    pad = " " * len(first)
    return "\n".join(f"{first if i == 0 else pad}{line}" for i, line in enumerate(lines))


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


def _common(command: argparse.ArgumentParser, demo_help: str) -> None:
    command.add_argument(
        "--provider",
        choices=["claude", "demo"],
        default="claude",
        help=f"LLM provider; 'demo' {demo_help} offline (default: %(default)s)",
    )
    command.add_argument("--model", help="model id for the provider (default: provider's)")
    command.add_argument(
        "--effort", choices=["low", "medium", "high", "xhigh", "max"], default="high"
    )
    command.add_argument("--max-turns", type=int, default=40)
    command.add_argument(
        "--console",
        nargs="?",
        const="auto",
        metavar="URL",
        help="send approvals and activity to the anysoar console: the running one "
        "(found through its console.env), or the one at URL with ANYSOAR_APPROVAL_TOKEN",
    )
    command.add_argument(
        "--server-arg",
        action="append",
        default=[],
        metavar="ARG",
        help="extra argument for anysoar-mcp, e.g. --server-arg=--policy=policy.toml",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anysoar-agent",
        description="Reference AI agent for anysoar. Write actions ask for your approval.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    triage = commands.add_parser("triage", help="triage one phishing case")
    triage.add_argument("case_uid", help="the case to triage, e.g. case-0001")
    _common(triage, "replays a scripted triage of case-0002")
    watcher = commands.add_parser(
        "watch",
        help="keep triaging open cases as they appear, following SOAR switches",
    )
    _common(watcher, "notes each case for an analyst")
    watcher.add_argument(
        "--status",
        default=",".join(OPEN_STATUSES),
        help="case statuses to work on (default: %(default)s)",
    )
    watcher.add_argument("--interval", type=float, default=5.0, help="seconds between checks")
    watcher.add_argument("--max-cases", type=int, help="stop after this many cases")
    return parser


def _console(args: argparse.Namespace) -> tuple[str, str] | None:
    """The console's URL and submit token, if --console was given."""
    if args.console is None:
        return None
    if args.console != "auto":
        token = os.environ.get("ANYSOAR_APPROVAL_TOKEN")
        if not token:
            sys.exit("anysoar-agent: --console URL needs ANYSOAR_APPROVAL_TOKEN")
        return args.console, token
    path = connection_file()
    if not path.exists():
        sys.exit(f"anysoar-agent: no console running ({path} not found); start anysoar-console")
    try:
        return read_connection(path)
    except ValueError as exc:
        sys.exit(f"anysoar-agent: {exc}")


@dataclass
class _Session:
    server: StdioServerParameters
    reporter: ConsoleReporter | None
    on_event: Callable[[AgentEvent], Awaitable[None]]


def _session(args: argparse.Namespace) -> _Session:
    """The MCP server to start, and where the agent's activity goes."""
    console = _console(args)
    server_args, env = list(args.server_arg), dict(os.environ)
    printer = event_printer()
    reporter = None
    if console is not None:
        url, token = console
        # Approvals go to the console instead of this terminal.
        server_args += ["--approver", "http", "--approval-url", url]
        env["ANYSOAR_APPROVAL_TOKEN"] = token
        reporter = ConsoleReporter(url, token)
        print(f"anysoar-agent: approvals and activity go to the console at {url}", file=sys.stderr)

    async def on_event(event: AgentEvent) -> None:
        printer(event)
        if reporter is not None:
            await reporter(event)

    server = StdioServerParameters(
        command=sys.executable, args=["-m", "anysoar.mcp", *server_args], env=env
    )
    return _Session(server, reporter, on_event)


async def _triage(args: argparse.Namespace, model: Model) -> AgentResult:
    session = _session(args)
    try:
        if session.reporter is not None:
            await session.reporter.report(
                "start", text=f"{model.name} triaging {args.case_uid}", case=args.case_uid
            )
        return await run_triage(
            args.case_uid,
            model,
            session.server,
            terminal_approver(),
            max_turns=args.max_turns,
            on_event=session.on_event,
        )
    finally:
        if session.reporter is not None:
            await session.reporter.aclose()


async def _watch(args: argparse.Namespace) -> list[Handled]:
    session = _session(args)
    statuses = [s.strip() for s in args.status.split(",") if s.strip()]
    shared = None if args.provider == "demo" else _model(args)

    def model_for(case_uid: str) -> Model:
        return shared if shared is not None else generic_demo_model(case_uid)

    async def on_case(soar: str, case_uid: str, case: dict[str, Any]) -> None:
        title = case.get("message") or ""
        print(f"\n=== {soar}: {case_uid} {title}", file=sys.stderr)
        if session.reporter is not None:
            name = shared.name if shared is not None else "demo"
            await session.reporter.report(
                "start", text=f"{name} triaging {case_uid} on {soar}", case=case_uid, soar=soar
            )

    async def on_done(done: Handled) -> None:
        if done.switched_to is None:
            return
        warning = (
            f"The SOAR switched from {done.soar} to {done.switched_to} while {done.case_uid} "
            "was in progress; its later actions went to the new SOAR and may have failed."
        )
        print(f"anysoar-agent: {warning}", file=sys.stderr)
        if session.reporter is not None:
            await session.reporter.report("text", text=warning)

    print(
        f"anysoar-agent: watching for {', '.join(statuses)} cases every {args.interval:g}s "
        "(Ctrl-C to stop)",
        file=sys.stderr,
    )
    try:
        async with Client(
            session.server,
            elicitation_callback=_elicitation_callback(terminal_approver()),
            client_info=Implementation(name="anysoar-agent", version="0.0.0"),
        ) as client:
            return await watch(
                client,
                model_for,
                statuses=statuses,
                interval=args.interval,
                max_cases=args.max_cases,
                max_turns=args.max_turns,
                on_event=session.on_event,
                on_case=on_case,
                on_done=on_done,
            )
    finally:
        if session.reporter is not None:
            await session.reporter.aclose()


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    if args.command == "watch":
        with contextlib.suppress(KeyboardInterrupt):
            handled = asyncio.run(_watch(args))
            print(f"anysoar-agent: triaged {len(handled)} cases", file=sys.stderr)
        return
    model = _model(args)
    print(f"anysoar-agent: {model.name} triaging {args.case_uid}", file=sys.stderr)
    result = asyncio.run(_triage(args, model))
    usage = result.usage
    print(
        f"anysoar-agent: {result.turns} turns; tokens in {usage.input_tokens} "
        f"({usage.cached_input_tokens} cached), out {usage.output_tokens}",
        file=sys.stderr,
    )
    print(result.text)
    if result.stop != "end":
        sys.exit(f"anysoar-agent: stopped early ({result.stop})")
