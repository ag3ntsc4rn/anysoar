# anysoar-console

A local web console for people supervising AI agents that use anysoar. Agents' write actions
wait here until you approve or reject them. It is an example app and is not published to PyPI.

```bash
uv run anysoar-console
```

It listens on `127.0.0.1:8765` and prints a sign-in link. Open it in your browser.

## How approvals reach it

anysoar's MCP server sends approval requests here when started with `--approver http`
(see `anysoar.policy.HttpApprover` for the protocol). The console writes the address and a
*submit token* to `~/.local/state/anysoar/console.env` (readable only by you) for that:

```bash
set -a; source ~/.local/state/anysoar/console.env; set +a
anysoar-mcp --approver http
```

## Security

- **Asking is not deciding.** The submit token only lets anysoar ask for approval. Deciding
  takes a browser session, which only the printed sign-in link starts; that link's token is
  never saved. An agent that obtained the submit token still could not approve anything.
- Browser decisions also need a custom request header, so other websites cannot submit them.
- The console listens on localhost only and rejects requests for other host names, which
  blocks DNS-rebinding attacks.
- Approvals that nobody decides in time (`anysoar-mcp --approval-timeout`, default 300 s)
  are denied and shown as expired.
