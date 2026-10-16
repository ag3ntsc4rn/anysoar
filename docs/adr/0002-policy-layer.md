# ADR 0002: The policy layer and how agents get approval

- **Status:** accepted
- **Date:** 2026-10-15

## Context

anysoar lets AI agents act on a SOAR: close cases, add notes, run playbooks that block senders
or disable accounts. An agent can be wrong, manipulated by content it reads (prompt injection
in an alert is a realistic threat), or simply over-eager. Every operation an agent can request
needs a guardrail that the agent itself cannot bypass, and a record of what happened.

The guardrail sits between the MCP server and the driver. It has to work the same for every
driver and every MCP client.

## Decision

### Tiers and decisions

Every driver operation has a tier (`read`, `write`, `destructive`; see `CAPABILITY_TIERS`). A
playbook run takes the tier the driver declares for that playbook. A `Policy` maps each action
to a decision:

| Tier | Default decision |
|---|---|
| read | allow |
| write | require approval |
| destructive | deny |

Operators can override decisions per capability or per playbook (a TOML file for
`anysoar-mcp`). A single decision for `run_playbook` as a whole is rejected, because it would
also cover destructive playbooks.

### One enforcement point

`GuardedDriver` wraps any driver and is itself a `Driver`. The MCP server only ever holds a
guarded driver, so there is no code path from a tool to the SOAR that skips the policy. For
each call it:

1. builds an `Action` (capability, tier, one-line summary, arguments)
2. records a `requested` audit event with the policy decision
3. checks the kill switch
4. denies, or asks the approver, according to the decision
5. checks the kill switch again if it asked (approvals take time)
6. calls the driver and records `completed` or `failed`

With an approver that approves everything, a guarded driver passes the driver contract suite.
This shows the guard changes nothing except what the policy refuses.

### Fail closed

Every unknown or broken state ends in a denial (`PolicyDeniedError`, with a `DenialReason`),
before the SOAR is called:

- no approver, an approver that cannot ask anyone, or an approval timeout
- a playbook whose tier cannot be determined (the driver cannot list playbooks), which is
  treated as destructive
- an audit log that cannot record the request or the approval
- a kill switch file that exists but cannot be read

Failing to record the final `completed` event is the one exception. That failure is logged,
but the result is still returned, because the SOAR has already acted and hiding the result
would mislead the agent.

### Kill switch

The kill switch stops every operation, reads included. It can be engaged in process (for a
future console) or by creating a file, so an operator can stop an agent from any shell
without its cooperation. It does not interrupt calls already running in the SOAR.

### Approval over MCP

From protocol version 2026-07-28, an MCP server cannot send requests to the client in the
middle of a tool call. Instead, the SDK's resolvers run *before* the tool body and may ask the
user through elicitation. anysoar's tools therefore:

1. preview the exact `Action` through the guard (`GuardedDriver.action`) in a resolver;
2. elicit a yes/no form showing the action's summary, but only if the policy requires
   approval, the kill switch is off and the client supports form elicitation;
3. hand the answer to the guard through `ElicitationApprover`, so the decision, audit and
   kill switch checks still happen in one place.

Clients without elicitation get an `approval_unavailable` denial for writes and can still
read. A guard with any other approver, such as a console, never elicits.

## Trust boundary

Approval by elicitation is only as trustworthy as the MCP client that shows the question. A
client that answers elicitations automatically, or lets the model answer them, defeats
approvals. The SDK seals the state carried between rounds (AES-GCM), so a client cannot forge
an earlier answer, but the answer itself always comes from the client. Deployments that cannot
trust the client should use an out-of-band approver; that is the planned console in phase 6.

**Update (phase 6):** `HttpApprover` sends approval requests to an approval service over
HTTP ([protocol](../approval-service.md)), and the console in `apps/console` is one. The
service holds two credentials apart: the token anysoar uses can only *ask*; deciding needs a
person's session. A compromised or prompt-injected agent that obtains anysoar's token still
cannot approve its own actions.

The audit log records SOAR data (arguments, summaries), so it is created readable only by the
current user.

## Consequences

- Agents see the policy before acting: `describe_soar` and `list_playbooks` report each
  decision, and denied capabilities are not offered as tools at all.
- Driver authors do nothing for safety beyond declaring playbook tiers honestly (CONTRIBUTING,
  rule 4).
- Writes cannot run in fully unattended mode unless an operator explicitly allows them in the
  policy, which is the intended default for a demo-grade project.
- The policy is per server process. Per-user or per-agent policies would need identity from
  the transport (for example, authenticated HTTP) and are out of scope for now.
