# anysoar for SOAR vendors

anysoar is an open-source (Apache 2.0) layer between AI agents and SOAR platforms. Agents
use one interface, an [MCP](https://modelcontextprotocol.io) server, and anysoar translates
to your platform's API through a **driver**. Between the two sits a policy layer: reads run
freely, writes wait for a person's approval, destructive actions are blocked, everything is
written to an audit log, and a kill switch stops it all.

This page is for people at SOAR vendors who are considering a driver for their platform.

## What a driver gives your customers

- **AI agents that work with your platform today**, whichever agent framework or LLM they
  use: anything that speaks MCP, including Claude, GPT-based tools and custom agents.
- **The guardrails their security teams ask for before letting an agent act**: approval for
  every write, destructive actions blocked, an audit trail of what was asked, decided and
  run, and a kill switch, all outside the agent.
- **[OCSF](https://schema.ocsf.io) data**: alerts, cases and indicators as OCSF Detection
  Findings, Incident Findings and observables, so the same agent works across platforms.

anysoar complements a vendor's own MCP server rather than competing with it: it is the
vendor-neutral policy and data layer for customers who run more than one tool, or who need
approvals and audit in a form they control.

## What a driver is

A Python class that implements the operations your platform supports: listing and reading
alerts and cases, adding notes, closing cases with a verdict, enriching indicators, and
running playbooks. A driver implements only what fits; the rest is reported as unsupported
and agents adapt. [CONTRIBUTING.md](../CONTRIBUTING.md#writing-a-driver) has the details and
a skeleton.

Every driver must pass the same **contract test suite** (`anysoar.testing.DriverContract`),
run against a real instance of the platform. That is the bar for calling a driver supported,
and it means you know exactly what "done" is.

## Two ways to have a driver

| | Built in | Your own package |
|---|---|---|
| Where the code lives | this repository | your repository, e.g. `anysoar-<vendor>` on PyPI |
| Who maintains and releases it | anysoar's maintainers | you |
| How users install it | `pip install "anysoar[<vendor>]"` | `pip install anysoar-<vendor>` |
| Listed in the README as | built in | vendor-maintained |

Either way, `anysoar-mcp --driver <vendor>` starts it. A package provides a driver by
declaring an `anysoar.drivers` entry point; see
[Packaging](../CONTRIBUTING.md#packaging). The driver API changes only under the rules in
[Stability of the driver API](../CONTRIBUTING.md#stability-of-the-driver-api).

## What helps most

In rough order of how much it helps, and how little it costs you:

1. **A test instance**: a sandbox, developer tenant, community edition or not-for-resale
   licence. Without one, a driver can only be built from your documentation and tested
   against a fake, and cannot be listed as supported.
2. **A technical contact** for API questions (what a status means, how paging behaves,
   rate limits).
3. **A review** of a driver before it is called supported.
4. **An engineer who builds or maintains the driver**, in this repository or in your own
   package.
5. **A listing** in your integrations marketplace or technology partner programme.

## Ground rules

- Drivers are built from **public documentation** only, and tested with **synthetic data**.
  No customer data, no private APIs.
- anysoar uses your product name only to say what a driver connects to; no logos or
  endorsement are implied.
- Contributions are under Apache 2.0 with a [DCO](https://developercertificate.org)
  sign-off; there is no contributor licence agreement to sign.

## Getting in touch

Open a [New driver request](https://github.com/ag3ntsc4rn/anysoar/issues/new?template=new_driver.yml)
issue and say you work for the vendor. The
[demo](../demo) shows an agent switching from a mock SOAR to a real one without a restart;
it takes a few minutes to run locally.
