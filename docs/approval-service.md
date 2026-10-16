# Building an approval service

anysoar asks a person before running a write action. By default it asks through the MCP
client. With `anysoar-mcp --approver http` it asks an **approval service** over HTTP instead:
the [console](../apps/console) is one, and you can build your own, for example a chat bot
that posts each request to a channel, or a bridge to a ticketing system.

```bash
export ANYSOAR_APPROVAL_TOKEN=...            # never a flag, so it stays out of process lists
anysoar-mcp --approver http --approval-url https://approvals.internal.example \
            --approval-timeout 300
```

In Python, pass `anysoar.policy.HttpApprover(url, token)` to `GuardedDriver`.

## Protocol

Every request carries `Authorization: Bearer <token>` and JSON bodies.

| Method | Path | Body or query | Response |
|---|---|---|---|
| `POST` | `/api/approvals` | `{"action": Action, "actor": str \| null}` | `201 {"id": str}` |
| `GET` | `/api/approvals/<id>` | `?wait=<seconds>` | `{"status", "approver", "reason"}` |
| `POST` | `/api/approvals/<id>/expire` | `{}` | any 2xx |

- **`action`** is the `Action` anysoar wants to run: `capability`, `tier` (`write` or
  `destructive`), `summary` (one line to show a person, e.g. `Close case case-0002 as benign`),
  and `arguments`. **`actor`** names the client asking, e.g. `mcp:anysoar-agent`.
- **`status`** is `pending`, `approved` or `rejected`. anysoar polls until it is not
  `pending`; the service may hold each request open for up to `wait` seconds until the status
  changes. `approver` and `reason` are recorded in anysoar's audit log.
- **`expire`** means anysoar stopped waiting (its `--approval-timeout` passed) and has denied
  the action. Mark the request so nobody approves something that will never run.

anysoar treats any problem as "no approval": an unreachable service, a `401`/`403`, another
error status, invalid JSON or an unknown status all deny the action.

## Security requirements

1. **The token must not be able to decide.** It lets anysoar *ask*. Decisions must come from
   a person through a separate, authenticated channel. If the token could approve, an agent
   that obtained it, for example through prompt injection, could approve its own actions.
2. **Show the summary and arguments as text.** They can contain attacker-written content
   copied from emails or alerts. Never render them as HTML or follow links in them.
3. **Record who decided.** Return a real `approver`, so the audit log says who approved what.
4. **Decide once.** Reject decisions on requests that are no longer `pending`.

The console in [`apps/console`](../apps/console) follows all four; read
[`app.py`](../apps/console/src/anysoar_console/app.py) for a small, complete implementation.
