# anysoar

**One interface for AI agents to operate any SOAR platform, with guardrails built in.**

Agents talk to anysoar; anysoar translates to whichever SOAR sits underneath through a
per-vendor driver. Swapping SOARs means swapping a driver, not rewriting agents. Every action
goes through a policy layer: reads run freely, writes wait for a person's approval,
destructive actions are blocked, everything is audited, and a kill switch stops it all.

> **Status: pre-alpha.** Expect breaking changes. Source, docs and a one-command demo:
> <https://github.com/ag3ntsc4rn/anysoar>

![The anysoar console: an agent's action waiting for approval, and its reasoning as it works](https://raw.githubusercontent.com/ag3ntsc4rn/anysoar/main/docs/images/console.png)

## Install

```bash
pip install anysoar                       # models, driver interface, policy layer, mock SOAR
pip install "anysoar[mcp]"                # + the MCP server (anysoar-mcp)
pip install "anysoar[shuffle]"            # + the Shuffle driver
pip install "anysoar[tines]"              # + the Tines driver
pip install "anysoar[testing]"            # + the contract test suite for driver authors
```

Python 3.12 or newer.

## What's in it

- **Drivers:** a mock SOAR with a synthetic phishing scenario,
  [Shuffle](https://shuffler.io) and [Tines](https://www.tines.com). `SwitchableDriver` switches between SOARs while agents keep
  running.
- **OCSF data model:** alerts are Detection Findings, cases are Incident Findings, indicators
  are observables ([OCSF](https://schema.ocsf.io) 1.9.0), whatever the SOAR.
- **Policy layer:** `GuardedDriver` wraps any driver with approvals (from the MCP client or
  an approval service over HTTP), an audit log and a kill switch.
- **MCP server:** `anysoar-mcp` offers each SOAR operation as a tool to any MCP client.
- **Driver contract tests:** `anysoar.testing.DriverContract`, which every driver passes.

## Use it from Python

The mock driver needs no SOAR:

```python
import asyncio

from anysoar.drivers.mock import MockDriver
from anysoar.interface import CaseQuery
from anysoar.models import IncidentFindingStatusId, Observable, ObservableTypeId
from anysoar.policy import GuardedDriver


async def main() -> None:
    # GuardedDriver applies the policy: reads run, writes would need an approver.
    async with GuardedDriver(MockDriver()) as soar:
        open_cases = await soar.list_cases(
            CaseQuery(status_ids=frozenset({IncidentFindingStatusId.NEW}))
        )
        for case in open_cases.items:
            print(case.metadata.uid, case.message)

        sender = Observable(type_id=ObservableTypeId.EMAIL_ADDRESS, value="it-support@example.net")
        result = await soar.enrich_indicator(sender)
        print(result.observable.reputation)


asyncio.run(main())
```

Use `ShuffleDriver(url, api_key)` from `anysoar.drivers.shuffle` for Shuffle, or
`TinesDriver(url, api_key)` from `anysoar.drivers.tines` for Tines; the rest of the code
stays the same.

## Use it from an MCP client

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

The agent gets one tool per operation the SOAR supports, plus `describe_soar`. Write actions
ask you in your MCP client, or in a web console with `anysoar-mcp --approver http`. Run
`anysoar-mcp --help` for the options, including `--driver mock,shuffle,tines` and `--policy`.

## Learn more

- [Repository and full README](https://github.com/ag3ntsc4rn/anysoar)
- [The end-to-end demo](https://github.com/ag3ntsc4rn/anysoar/tree/main/demo)
- [Writing a driver](https://github.com/ag3ntsc4rn/anysoar/blob/main/CONTRIBUTING.md#writing-a-driver)
- [Building an approval service](https://github.com/ag3ntsc4rn/anysoar/blob/main/docs/approval-service.md)
- [Changelog](https://github.com/ag3ntsc4rn/anysoar/blob/main/CHANGELOG.md)

Licensed under Apache 2.0.
