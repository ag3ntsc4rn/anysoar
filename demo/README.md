# The anysoar demo

An AI agent triages phishing cases while you supervise it from the anysoar console. Halfway
through, you switch the SOAR underneath it from a mock to [Shuffle](https://shuffler.io),
a real SOAR running locally, and the same running agent carries on without a restart.

```bash
demo/run.sh            # offline: a scripted agent, no API key needed
demo/run.sh --claude   # Claude does the triage (needs ANTHROPIC_API_KEY; costs cents per case)
```

You need [uv](https://docs.astral.sh/uv/) and Docker (Docker Desktop on a Mac, with at least
4 GB of memory). The first run pulls Shuffle's images and takes a few minutes; see
[shuffle/README.md](shuffle/README.md) for what the local Shuffle lab changes on your machine.

## What the script does

1. Starts the [local Shuffle lab](shuffle) with its incident UI, and loads the synthetic
   phishing scenario into it: the same three cases the mock SOAR has.
2. Points anysoar at the mock SOAR.
3. Starts the console and prints its sign-in link.
4. Starts the agent with `anysoar-agent watch`: one long-running agent that triages each
   open case, connected to `anysoar-mcp --driver mock,shuffle`. Its write actions wait for
   you in the console.

Press Ctrl-C to stop the agent; the script then stops the console. The Shuffle lab keeps
running (`demo/shuffle/down.sh` stops it).

## Walkthrough

1. **Open the console** with the printed sign-in link. The agent starts on the mock SOAR:
   its reasoning and tool calls appear in the *Agent* panel.
2. **Approve or reject** each action it asks for. Add a reason; it goes into the audit log.
   Rejected actions never reach the SOAR, and the agent carries on.
3. **Switch the SOAR.** When the agent panel shows *Finished* for a case, click **shuffle**
   next to *SOAR* in the console header. The agent's next case comes from Shuffle: it now
   has fewer tools (Shuffle has no alerts or indicator enrichment) and works on Shuffle's
   incidents. The audit trail's *SOAR* column shows where each call went.
4. **See it in Shuffle.** Open Shuffle's incident UI at http://localhost:3002 (user `admin`,
   password in `demo/shuffle/.env.local`): the agent's notes are there, marked as AI-handled.
5. **Stop everything** with *Stop all actions*. Every call is denied, reads included, until
   you click *Resume*.

## Things to know

- **Switch between cases.** Every call goes to the SOAR that is active at that moment, so a
  case the agent is in the middle of continues on the new SOAR, where it does not exist;
  those calls fail (nothing is written to the wrong place) and the agent reports it.
- **Re-running** reloads the scenario into Shuffle and starts again on the mock. The mock
  forgets everything when the agent stops.
- The demo uses only synthetic data: `example.com/.net/.org` addresses and documentation IP
  ranges.
