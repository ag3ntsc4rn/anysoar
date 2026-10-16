# Local TheHive lab

A local [TheHive](https://strangebee.com/thehive/) 5.8.1 with
[Cortex](https://github.com/TheHive-Project/Cortex) 4.1.0, for developing and demoing
anysoar's TheHive driver. TheHive holds alerts and cases; Cortex is its companion analysis
engine (no relation to Palo Alto's Cortex XSOAR), which runs *analyzers* that look up an
indicator and report on it. Everything runs natively on Apple Silicon or x86 with Docker.

```bash
./up.sh               # start; the first run generates secrets and sets everything up
./down.sh             # stop, keeping data
./down.sh --purge     # remove containers, data and .env.local
```

Then load anysoar's synthetic phishing scenario (re-running resets it):

```bash
uv run demo/thehive/seed.py
```

It creates the mock driver's eight alerts with their indicators, and its three cases, each
made from its alerts as an analyst would: the first alert becomes the case and the others are
merged into it. Notes become comments, and the closed case is closed with its verdict. It
prints the case numbers and the command to let the reference agent triage one. Case numbers
change on every run: TheHive never reuses them.

`up.sh` prints the web UI addresses, how many days the trial license has left, and the
`THEHIVE_URL` / `THEHIVE_API_KEY` variables the driver uses. Passwords and API keys are
random per install and live only in `.env.local`, which is git-ignored.

On the first run it sets both services up through their APIs, so nothing needs clicking:

- **TheHive** gets its default admin password (`secret`) replaced, an `anysoar`
  organisation, a service account `anysoar@anysoar.lab` with an API key (what the driver
  uses), and a person login `analyst@anysoar.lab` for the web UI at http://localhost:9000.
- **Cortex** gets an `anysoar` organisation, an API key for TheHive, and three analyzers
  that need no API key: DShield (IP addresses), Abuse_Finder (IPs, domains, URLs and email
  addresses) and CIRCL hashlookup (file hashes). Its web UI is at http://localhost:9001
  (user `admin`).
- TheHive is connected to Cortex, so analyzers can be run on any observable.

## Before you run it

- **Trial license.** TheHive starts on a 14-day Platinum trial and then turns read-only
  until it gets a license. The lab doesn't use one: when the trial runs out, `./down.sh
  --purge && ./up.sh` starts over with a fresh trial (and new secrets). StrangeBee also
  offers a free Community license (2 users, 1 organisation) on request, if you'd rather keep
  the data.
- **Analyzers send lookups to public services.** DShield, RIPEstat and CIRCL see the
  indicators you analyze. anysoar's demo data is synthetic (documentation IP ranges and
  `example.com` addresses); don't analyze anything you wouldn't post publicly.
- **It controls Docker on your machine.** Cortex mounts the Docker socket, because it runs
  each analyzer in its own short-lived container, and its entrypoint hands the socket to its
  own user. Use it as a local lab, not next to anything sensitive in Docker.
- **Resources:** about 4.5 GB of images (plus about 200 MB per analyzer, pulled on first
  use), and about 4 GB of memory while running. Give Docker Desktop at least 6 GB, or 8 GB
  to run it next to the Shuffle lab.
- **Ports** are bound to 127.0.0.1 only: 9000 (TheHive) and 9001 (Cortex).

## How this differs from StrangeBee's compose files

- Versions are pinned, and ports are not exposed beyond localhost.
- **No Cassandra.** TheHive keeps its data in its embedded local database, which is fine for
  a single node, and indexes it in the Elasticsearch that Cortex needs anyway.
- **No Nginx.** The services are served over plain HTTP on localhost.
- Elasticsearch is not published and runs without security.
- Users, API keys, analyzers and the TheHive–Cortex connection are created at startup.
- Cortex accepts basic authentication (`cortex.conf`) so `up.sh` can set it up before any
  API key exists.

## What the driver does with it

`--driver thehive` (or `TheHiveDriver`) reads `THEHIVE_URL` and `THEHIVE_API_KEY`, which
`up.sh` prints. Alerts and cases are TheHive's; enrichment runs the analyzers above through
TheHive and waits for their reports, which also appear on the observable in TheHive's UI.
With documentation addresses, Abuse_Finder fails (whois refuses them) and says so; DShield
reports them as safe.

The driver's contract tests run against this lab:

```bash
set -a && source demo/thehive/.env.local && set +a
THEHIVE_URL=http://127.0.0.1:9000 ANYSOAR_LIVE_THEHIVE=1 uv run pytest packages/anysoar/tests/drivers/thehive
```

They create synthetic alerts and cases, and delete them afterwards.

## Notes

- **The service account can delete.** TheHive's built-in `analyst` profile includes deleting
  cases and alerts. anysoar never deletes anything (the contract tests clean up after
  themselves), but the API key could. If that matters, give the account a profile without
  those permissions.

- **Analyzer jobs** exchange files with Cortex through `.cortex-jobs/` (git-ignored), which
  must have the same path inside the Cortex container as on your machine.
- **Lost the API keys?** If the data was deleted but `.env.local` kept, `up.sh` reports that
  TheHive rejects its key; reset with `./down.sh --purge && ./up.sh`.
- Analyzer images come from `ghcr.io/thehive-project`; Cortex pulls each one the first time
  it runs.
