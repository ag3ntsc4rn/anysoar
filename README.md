# anysoar

**One interface for AI agents to operate any SOAR platform.**

[![CI](https://github.com/ag3ntsc4rn/anysoar/actions/workflows/ci.yml/badge.svg)](https://github.com/ag3ntsc4rn/anysoar/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> **Status: pre-alpha.** The OCSF-aligned data model, the driver interface, the policy
> layer, the MCP server, a reference triage agent, and two drivers exist: a mock (an
> in-memory fake SOAR) and [Shuffle](https://shuffler.io), the first real SOAR. Expect
> breaking changes.

## The problem

Security teams increasingly want to bring their own AI agents into the SOC: to triage alerts,
enrich indicators, and drive response. But every SOAR platform exposes a different API, data
model and playbook mechanism. An agent written against one SOAR has to be rewritten for the
next, which locks teams into whichever vendor they started with.

## The idea

anysoar is a vendor-agnostic adapter. Agents talk to anysoar; anysoar translates to whichever
SOAR sits underneath through a per-vendor **driver**. Swapping vendors means swapping a driver,
not rewriting agents.

- **One agent interface**: an [MCP](https://modelcontextprotocol.io) server exposing SOAR
  operations as tools.
- **One data model**: alerts, cases, observables and actions aligned with
  [OCSF](https://schema.ocsf.io) rather than a home-grown schema.
- **Guardrails built in**: a policy layer between the agent and the SOAR. Read actions run
  freely, write actions need human approval, destructive actions are blocked, and everything is
  written to an audit log with a kill switch.

## Architecture

```mermaid
flowchart LR
    A["AI agent(s)"] -->|MCP tools| M["anysoar MCP server"]
    M --> P["Policy layer<br/>tiers · approvals · audit log · kill switch"]
    P --> I["Driver interface<br/>OCSF-aligned models"]
    I --> D1["Shuffle driver"]
    I --> D2["Mock driver"]
    I --> D3["Your driver"]
    D1 --> S1[("Shuffle")]
    D2 --> S2[("In-memory fake SOAR")]
    D3 --> S3[("Any SOAR")]
```

## Install

```bash
pip install anysoar
```

That gives you the data model, the driver interface, the policy layer and the mock driver.
Optional extras add the rest:

```bash
pip install "anysoar[mcp]"      # MCP server (anysoar-mcp)
pip install "anysoar[testing]"  # driver contract test suite
pip install "anysoar[shuffle]"  # Shuffle driver
```

## Use it from an MCP client

`anysoar-mcp` runs the MCP server over stdio. Point your MCP client at it, for example with
[uv](https://docs.astral.sh/uv/) fetching it from PyPI:

```json
{
  "mcpServers": {
    "anysoar": {
      "command": "uvx",
      "args": ["--from", "anysoar[mcp]", "anysoar-mcp"]
    }
  }
}
```

From a checkout, use `"command": "uv"` with
`"args": ["run", "--directory", "/path/to/anysoar", "anysoar-mcp"]` instead.

The agent gets one tool per SOAR operation plus `describe_soar`. Run `anysoar-mcp --help`
for options: `--driver` (`mock` or `shuffle`), `--policy`, `--audit-log` and `--kill-switch`.

## Guardrails

- **Reads** run freely. **Writes** (add a note, close a case, run a playbook) need your
  approval: your MCP client shows the action and asks you to approve it. Clients without
  [elicitation](https://modelcontextprotocol.io) support can read but not write.
- **Destructive** playbooks, such as disabling an account, are denied.
- **Everything is audited** to `~/.local/state/anysoar/audit.jsonl`: each request, its
  policy decision, the approval and the outcome.
- **Kill switch:** `touch ~/.local/state/anysoar/STOP` denies every operation until you delete
  the file.
- Change the defaults with a policy file:

  ```toml
  # anysoar-mcp --policy policy.toml
  [capabilities]
  add_note = "allow"              # notes no longer need approval

  [playbooks]
  pb-notify-reporter = "allow"
  ```

Approval is only as trustworthy as the MCP client that asks you; see
[ADR 0002](docs/adr/0002-policy-layer.md) for the design and its trust boundary.

## Watch an agent triage a case

[`apps/agent`](apps/agent) is a reference phishing-triage agent. It is a plain MCP client,
works with any LLM backend (Claude first), and asks you before every write. From a checkout,
with no API key:

```bash
uv sync
uv run anysoar-agent triage case-0002 --provider demo
```

Drop `--provider demo` and set `ANTHROPIC_API_KEY` to let Claude do the triage.

## Swap the SOAR underneath

The same agent works on [Shuffle](https://shuffler.io) without changes. Run a local Shuffle
with [`demo/shuffle`](demo/shuffle) (Docker), load the same phishing scenario into it, and
point anysoar at it:

```bash
demo/shuffle/up.sh --ui          # Shuffle, plus its incident UI on http://localhost:3002
uv run demo/shuffle/seed.py      # the scenario's cases and playbooks; prints the case ids
export SHUFFLE_URL=http://127.0.0.1:5001
export SHUFFLE_API_KEY="$(grep ^SHUFFLE_API_KEY= demo/shuffle/.env.local | cut -d= -f2)"
uv run anysoar-agent triage <case id> --server-arg=--driver=shuffle
```

Shuffle offers fewer operations than the mock (no alerts, no indicator enrichment), so the
agent is offered fewer tools and adapts: without reputation data it reports a verdict as
unconfirmed instead of guessing. Its notes and case closures show up in Shuffle's own UI.

## Use it from Python

The mock driver needs no SOAR. It serves a synthetic phishing scenario with alerts, cases,
enrichment and playbooks. After `pip install anysoar`:

```python
import asyncio

from anysoar.drivers.mock import MockDriver
from anysoar.models import Observable, ObservableTypeId


async def main() -> None:
    async with MockDriver() as soar:
        for alert in (await soar.list_alerts()).items:
            print(alert.finding_info.uid, alert.finding_info.title)

        sender = Observable(type_id=ObservableTypeId.EMAIL_ADDRESS, value="it-support@example.net")
        result = await soar.enrich_indicator(sender)
        print(result.observable.reputation)

        run = await soar.run_playbook(
            "pb-block-sender", case_uid="case-0001", inputs={"sender": sender.value}
        )
        while not run.status.is_finished:
            run = await soar.get_playbook_run(run.uid)
        print(run.status)


asyncio.run(main())
```

## Roadmap

1. **Data model and driver interface** (done): OCSF-aligned models; a driver contract with
   capability discovery.
2. **Mock driver** (done): an in-memory fake SOAR with synthetic alerts, plus a contract test
   suite every driver must pass.
3. **MCP server and policy layer** (done): core tools, action tiers, approvals, audit log,
   kill switch.
4. **Reference agent** (done): an example phishing-triage agent running against the mock
   driver, with pluggable LLM backends.
5. **Shuffle driver** (done): the first real SOAR, with the agent working unchanged.
6. **Console**: live agent reasoning and approve/reject for gated actions.
7. **Demo**: an end-to-end scenario including swapping the SOAR underneath a running agent.

## Repository layout

```
packages/anysoar/   the published Python package
apps/               example apps (agent, console); never published
demo/               demo environment and scenario
docs/               documentation
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security issues privately as described in
[SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE)
