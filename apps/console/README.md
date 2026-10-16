# anysoar-console

A local web console for people supervising AI agents that use anysoar. It is an example app
and is not published to PyPI.

![The anysoar console](../../docs/images/console.png)

```bash
uv run anysoar-console          # listens on 127.0.0.1:8765 and prints a sign-in link
```

Open the sign-in link. The console shows:

- **Waiting for you:** actions agents want to take, with Approve and Reject and an optional
  reason that goes into the audit log. Nothing runs until you decide.
- **Agent:** the agent's reasoning, tool calls and results as they happen.
- **Audit trail:** what anysoar requested, approved, ran, denied or failed, newest first,
  read from anysoar's audit log (`--audit-log`).
- **Stop all actions:** engages anysoar's kill switch (`--kill-switch`), which denies every
  operation, reads included, until you resume.

`--audit-log` and `--kill-switch` default to the same paths as `anysoar-mcp`, and
`--operator` sets the name recorded as the approver (default `console`).

## Connecting agents

The reference agent does it for you:

```bash
uv run anysoar-agent triage case-0002 --console
```

Any other setup: the console writes its address and a *submit token* to
`~/.local/state/anysoar/console.env` (readable only by you, removed when it stops). Start
anysoar's MCP server with them:

```bash
set -a; source ~/.local/state/anysoar/console.env; set +a
anysoar-mcp --approver http
```

Agents can also report their activity to `POST /api/agent/events` with the same token; see
[`anysoar_agent/console.py`](../agent/src/anysoar_agent/console.py). The approval protocol is
documented in [docs/approval-service.md](../../docs/approval-service.md).

## Security

- **Asking is not deciding.** The submit token lets anysoar ask for approval and agents
  report activity. Deciding, and the kill switch, take a browser session, which only the
  printed sign-in link starts; that link's token is never saved. An agent that obtained the
  submit token still could not approve anything or touch the kill switch.
- Browser actions also need a custom request header, so other websites cannot submit them.
- The console listens on localhost only and rejects other host names (DNS rebinding).
- What agents report is shown as text only, and is length-limited.
- Requests nobody decides in time (`anysoar-mcp --approval-timeout`, default 300 s) are
  denied and shown as expired.
