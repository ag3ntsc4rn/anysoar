# The anysoar demo

An AI agent triages phishing cases while you supervise it from the anysoar console. Halfway
through, you switch the SOAR underneath it from a mock to a real SOAR running locally, and
the same running agent carries on without a restart.

```bash
demo/run.sh                  # switch to Shuffle; offline: a scripted agent, no API key needed
demo/run.sh --soar thehive   # switch to TheHive, where the agent also looks up indicators
demo/run.sh --claude         # Claude does the triage (needs ANTHROPIC_API_KEY; cents per case)
```

The real SOAR is either [Shuffle](https://shuffler.io) (the default) or
[TheHive](https://strangebee.com/thehive/) with Cortex. On TheHive the agent's whole loop
runs on a real platform: it reads the case, looks its indicators up with Cortex analyzers,
and writes its note. Shuffle has no alerts or enrichment, so there it only reads and notes.

You need [uv](https://docs.astral.sh/uv/) and Docker (Docker Desktop on a Mac). Give Docker
at least 4 GB of memory for Shuffle, 6 GB for TheHive. The first run pulls the SOAR's images
and takes a few minutes; see [shuffle/README.md](shuffle/README.md) or
[thehive/README.md](thehive/README.md) for what each lab changes on your machine. TheHive
runs on a two-week trial license; its README says how to reset it.

## What the script does

1. Starts the [local Shuffle lab](shuffle) with its incident UI, or the
   [local TheHive lab](thehive) with `--soar thehive`, and loads the synthetic phishing
   scenario into it: the same cases the mock SOAR has.
2. Points anysoar at the mock SOAR.
3. Starts the console and prints its sign-in link.
4. Starts the agent with `anysoar-agent watch`: one long-running agent that triages each
   open case, connected to `anysoar-mcp --driver mock,shuffle` (or `mock,thehive`). Its
   write actions wait for you in the console.

The offline agent is scripted, but it adapts to the SOAR: it reads each case, looks up as
many as three of its indicators if the SOAR offers enrichment (URLs, IPs and hashes first;
email addresses only when known to be the sender), and notes the reputations it found.

Press Ctrl-C to stop the agent; the script then stops the console. The lab keeps running
(`demo/shuffle/down.sh` or `demo/thehive/down.sh` stops it).

## Walkthrough

1. **Open the console** with the printed sign-in link. The agent starts on the mock SOAR:
   its reasoning and tool calls appear in the *Agent* panel, under a status line saying
   what it is doing ("Working on case-0001 on mock…").
2. **Approve or reject** each action it asks for (the status line turns amber, "Waiting for
   your approval"). Add a reason; it goes into the audit log. Rejected actions never reach
   the SOAR, and the agent carries on.
3. **Switch the SOAR.** When the status line turns green ("Finished … A good moment to
   switch the SOAR"), click **shuffle** (or **thehive**) next to *SOAR* in the console header. The agent's next case comes from
   that SOAR. On Shuffle it has fewer tools (no alerts or indicator enrichment); on TheHive
   it looks indicators up with Cortex, about 10 seconds each. The audit trail's *SOAR*
   column shows where each call went.
4. **See it in the SOAR.** Shuffle's incident UI is at http://localhost:3002 (user `admin`,
   password in `demo/shuffle/.env.local`), where the agent's notes are marked AI-handled.
   TheHive is at http://localhost:9000 (user `analyst@anysoar.lab`, password in
   `demo/thehive/.env.local`): the notes are comments by the `anysoar` service account, and
   the analyzer reports are on each looked-up observable.
5. **Stop everything** with *Stop all actions*. Every call is denied, reads included, until
   you click *Resume*.

## Things to know

- **Switch between cases.** Every call goes to the SOAR that is active at that moment, so a
  case the agent is in the middle of continues on the new SOAR, where it does not exist;
  those calls fail (nothing is written to the wrong place) and the agent reports it.
- **Re-running** reloads the scenario into the lab and starts again on the mock. The mock
  forgets everything when the agent stops. TheHive gives the cases new numbers each time.
- **TheHive's lookups go to public services** (DShield, RIPEstat, CIRCL). The demo data is
  synthetic, but they see the values the agent looks up.
- The demo uses only synthetic data: `example.com/.net/.org` addresses and documentation IP
  ranges.
