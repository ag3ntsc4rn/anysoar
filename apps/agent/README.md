# anysoar-agent

A reference AI agent that triages user-reported phishing through anysoar's MCP server. It is
an example app, not published to PyPI.

It shows the point of anysoar: the agent is an ordinary MCP client with no SOAR-specific code,
so it keeps working when the SOAR underneath changes. It is also not tied to one LLM: the loop
talks to models through a small interface, and Claude is the first backend.

## Run the offline demo

No API key needed. The `demo` provider replays a scripted triage of the mock SOAR's
`case-0002`, a malicious invoice lure:

```bash
uv sync
uv run anysoar-agent triage case-0002 --provider demo
```

You will see the agent read the case, enrich the sender, attachment hash and source IP, and
then ask for your approval three times: to add a note, to run the block-sender playbook, and
to close the case. Answer `n` to see how the agent and the case handle a refusal.

## Run with Claude

```bash
export ANTHROPIC_API_KEY=...        # or: ant auth login
uv run anysoar-agent triage case-0001
```

Any case of the mock SOAR works: `case-0001` (credential phishing), `case-0002` (invoice
lure) and `case-0003` (already closed). Options:

- `--model`: defaults to `claude-opus-5-5`
- `--effort`: `low` to `max`, default `high`
- `--max-turns`: default 40
- `--server-arg`: passed to `anysoar-mcp`, e.g. `--server-arg=--policy=policy.toml`

The Claude backend uses adaptive thinking (shown as `(thinking)` lines), prompt caching, and
server-side fallbacks: if a safety classifier declines a request, the API retries it on a
recommended fallback model within the same call.

## What the agent may do

The agent can only do what anysoar's policy layer allows (see the main README):

- Reads run freely.
- Writes need your approval at the terminal. Your answer and optional reason go into the
  audit log. Without an interactive terminal, or on end of input, the answer is no.
- Destructive playbooks are denied, and the agent is told to recommend them instead.
- `touch ~/.local/state/anysoar/STOP` stops everything mid-run.

The system prompt in [`triage.py`](src/anysoar_agent/triage.py) tells the agent to treat
everything from the SOAR as untrusted data, because a phishing email is exactly where an
attacker would plant instructions for an AI.

## Add another model provider

The loop in [`agent.py`](src/anysoar_agent/agent.py) only knows the `Model` protocol in
[`model.py`](src/anysoar_agent/model.py):

```python
class MyModel:
    @property
    def name(self) -> str:
        return "myprovider:my-model"

    async def respond(self, system, transcript, tools) -> AssistantTurn:
        # 1. Convert `transcript` (UserMessage, AssistantTurn, ToolResults) and `tools`
        #    (ToolSpec with a JSON Schema) to your provider's request.
        # 2. Call the provider.
        # 3. Return AssistantTurn(stop=..., text=..., tool_calls=..., raw=<provider reply>).
        ...
```

Keep the provider's reply in `raw` if it must be sent back unchanged on the next request;
[`claude.py`](src/anysoar_agent/claude.py) does this for Claude's thinking blocks. Put the
provider's SDK in an optional extra, as `claude` is, then add it to `--provider` in
[`cli.py`](src/anysoar_agent/cli.py).

## Tests

```bash
uv run pytest apps/agent
```

Tests use a scripted model and a fake Claude client, so they need no API key. One live test
calls the Claude API and is skipped unless `ANYSOAR_LIVE_CLAUDE=1` is set.
