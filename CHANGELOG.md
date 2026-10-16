# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `anysoar.drivers.thehive`: `TheHiveDriver` for TheHive 5 (`anysoar[thehive]`), configured
  by `THEHIVE_URL`, `THEHIVE_API_KEY` and optionally `THEHIVE_ORGANISATION`.
  - Alerts are TheHive alerts (`list_alerts`, `get_alert`), the first real SOAR alerts in
    anysoar. OCSF statuses come from TheHive's alert stages; Ignored alerts are Suppressed,
    and the FalsePositive and Duplicate statuses set the verdict. Filters, sorting and
    paging run in TheHive. `get_alert` includes the alert's observables as indicators.
  - Cases are TheHive cases (`list_cases`, `get_case`, `add_note`, `close_case`); a case's
    uid is its number. Closing sets one of TheHive's closing statuses, which is also its
    verdict (TruePositive, FalsePositive, Indeterminate, Duplicated, Other); verdicts none of
    them names are closed as Other with a `verdict:<name>` tag. The closing comment is the
    case summary. `get_case` includes comments as notes, observables as indicators, and the
    alerts the case was made from as its findings.
  - The contract suite runs against a real TheHive with `ANYSOAR_LIVE_THEHIVE=1`, such as
    the local lab in `demo/thehive`.

## [0.3.0] - 2026-10-16

### Added

- `anysoar.drivers.tines`: `TinesDriver` for the Tines SOAR (`anysoar[tines]`), configured
  by `TINES_URL`, `TINES_API_KEY` and optionally `TINES_TEAM_ID`.
  - Playbooks are stories enabled for Send to Story. A run posts to the story's entry
    webhook, is found by a run id carried in the request, and finishes when it reaches an
    exit action, whose output is the run's result; it fails when the story's Send to Story
    timeout passes. Stories tagged `anysoar:destructive` are destructive. Checked against a
    real Tines Community Edition tenant.
  - Cases are Tines cases (`list_cases`, `get_case`, `add_note`, `close_case`). OCSF
    statuses come from Tines' open/closed status and sub-status; the verdict is kept as a
    `verdict:<name>` case tag. Tines Cases is a paid feature, so this part is built from
    Tines' API reference and tested against a fake; on tenants without it (such as the
    free Community Edition) `describe()` reports only the playbook operations.
  - The contract suite runs against a real tenant with `ANYSOAR_LIVE_TINES=1`.
- `anysoar-mcp --driver tines` serves a Tines tenant.

## [0.2.1] - 2026-10-16

### Fixed

- The package description on PyPI (the package README) still said the package only reserved
  its name and called the MCP server and Shuffle driver "planned". It now describes what the
  package ships, with an install guide, a working example and links that work on PyPI. A
  test keeps it in step with the package.

## [0.2.0] - 2026-10-16

### Added

- `list_cases`: a new read capability, `Driver.list_cases(CaseQuery)` returning a page of
  cases (most recently updated first, optionally filtered by status), so agents can find
  work instead of being handed case ids. Implemented by the mock and Shuffle drivers,
  guarded by the policy layer, offered as an MCP tool, and covered by the contract suite.
- `anysoar.drivers.SwitchableDriver` and `SoarSwitch`: switch the SOAR behind anysoar while
  agents keep running. A small file names the active SOAR; each call goes to the driver it
  names, and `describe()` reports that driver. `anysoar-mcp --driver mock,shuffle` serves
  several SOARs (switch file `--soar-switch`, default `~/.local/state/anysoar/SOAR`), and the
  MCP server adds and removes tools within a second of a switch. The active SOAR is
  reported under the name the switch uses for it.
- `anysoar.policy.HttpApprover`: approve actions through an approval service over HTTP, such
  as a web console or a chat bot. A small documented protocol (submit, wait for a decision,
  expire); the client's token can only ask for approval, never decide. Unreachable services
  and rejected tokens deny the action. Standard library only.
- `anysoar-mcp --approver http --approval-url URL` (token in `ANYSOAR_APPROVAL_TOKEN`) sends
  approvals to such a service instead of the MCP client; `--approval-timeout` sets how long
  to wait for a decision.

### Changed

- The policy layer checks what the driver supports with `describe()` at the time of each
  call, not with the driver class, so it honours drivers that narrow their capabilities and
  drivers whose SOAR changes at runtime. Unsupported calls still fail before any approval.

### Fixed

- Shuffle: comments written on someone's behalf can now be attributed to them and marked as
  not AI-written (`comment_entry` and `close_record` take `author` and `ai_handled`); the
  driver's own notes are still marked AI-written.

## [0.1.0] - 2026-10-16

### Added

- `anysoar.models`: Pydantic v2 models aligned with OCSF 1.9.0. Alerts are Detection Findings,
  cases are Incident Findings, indicators are observables; also enrichment, reputation, note,
  user, group, metadata and product objects, and the OCSF enums they use.
- Tests that check the models against a committed OCSF schema snapshot
  (`scripts/update_ocsf_snapshot.py` refreshes it).
- Core now depends on `pydantic>=2.14,<3`.
- `anysoar.interface`: the async driver contract. `Driver` base class, `Capability` discovery
  (a driver's capabilities are the operations it overrides), `ActionTier` (read, write,
  destructive) per capability, and `Playbook`, `PlaybookRun`, `Page`, `AlertQuery`,
  `IndicatorEnrichment` and `DriverInfo`.
- `anysoar.errors`: `CapabilityNotSupportedError`, `NotFoundError`, `DriverError`.
- `anysoar.drivers.mock`: `MockDriver`, an in-memory fake SOAR implementing every capability.
  It is seeded with a synthetic phishing scenario (8 alerts, 3 cases, 5 playbooks), gives
  deterministic enrichment, and advances playbook runs from queued to running to succeeded
  (or failed) one step per poll.
- `anysoar.testing.DriverContract`: a reusable contract test suite every driver must pass.
  Subclass it in a test module and override the `driver` fixture; tests for capabilities a
  driver doesn't report are skipped. Install with the new `testing` extra
  (`pip install "anysoar[testing]"`).
- `anysoar.policy`: the policy layer. `GuardedDriver` wraps any driver and runs every operation
  through a `Policy`: by default reads are allowed, writes need approval from an `Approver`, and
  destructive actions (including destructive playbooks) are denied. Overrides can be set per
  capability or per playbook. Approvals time out, and a playbook whose risk is unknown is
  treated as destructive.
- `anysoar.errors`: `PolicyDeniedError` with a `DenialReason`.
- Audit log: `GuardedDriver(audit_log=...)` records every step of every call (requested with
  the decision, approval, then completed, denied or failed) as `AuditEvent`s sharing a
  `call_uid`. `JsonlAuditLog` appends to a user-only JSONL file; `MemoryAuditLog` keeps events
  in memory. An action that cannot be recorded is not run.
- Kill switch: `GuardedDriver(kill_switch=KillSwitch(path))` denies every operation, reads
  included, while the switch is engaged in process (`engage()`) or the file at `path` exists.
  It is checked when each call arrives and again after approval.
- `anysoar.mcp`: `create_server(guarded_driver)` builds an MCP server (MCP Python SDK 2.3,
  `anysoar[mcp]`) with one tool per capability the driver reports, plus `describe_soar`.
  Tools take agent-friendly arguments (verdict and status names, ISO 8601 times) and return
  OCSF JSON. With `ElicitationApprover`, the user approves write actions in their MCP client
  (form elicitation, on both the 2026-07-28 and earlier protocols); the policy layer still
  decides, audits and checks the kill switch. Policy denials and SOAR errors are returned as
  readable tool errors.
- `GuardedDriver.action(capability, **arguments)` previews the `Action` a call would produce.
- `anysoar.drivers.shuffle`: `ShuffleDriver` for the Shuffle SOAR (`anysoar[shuffle]`). Shuffle
  workflows are playbooks: list, run (the inputs and case/alert context become the execution
  argument) and poll runs. Workflows tagged `anysoar:destructive` are destructive playbooks.
  Shuffle's inconsistent error responses map to `NotFoundError` and `DriverError`.
- Shuffle cases: `ShuffleDriver` reads and updates Shuffle incidents (the records the Shuffle
  Security UI shows) as cases: `get_case`, `add_note` and `close_case`. Shuffle's status
  numbering, activity-log comments and text verdicts are translated to and from OCSF; notes
  are written as UI comments marked AI-handled.
- `anysoar-mcp --driver shuffle` serves a Shuffle instance, configured by `SHUFFLE_URL` and
  `SHUFFLE_API_KEY`.
- `anysoar-mcp` command (also `python -m anysoar.mcp`): runs the MCP server over stdio with
  `--driver` (currently `mock`), `--policy` (TOML; unlisted tiers keep their defaults),
  `--audit-log` and `--kill-switch`, each also settable with an `ANYSOAR_*` environment
  variable. The audit log and kill switch are on by default, under
  `$XDG_STATE_HOME/anysoar/` (`~/.local/state/anysoar/`).

### Changed


- A case's uid is its `metadata.uid`, since an OCSF Incident Finding has no uid of its own.
- `anysoar-mcp` logs only warnings from the MCP SDK; its own messages stay at info.
- Using a feature whose optional dependencies are missing raises an error that names the
  extra to install (e.g. `pip install "anysoar[mcp]"`); `anysoar-mcp --help` works without it.
- The `shuffle` extra now depends on `httpx2` (used by the MCP and Anthropic SDKs) instead of
  `httpx`.

## [0.0.1] - 2026-10-15

### Added

- Initial package skeleton exposing `anysoar.__version__`, published to reserve the name.
- Optional extras `mcp` and `shuffle` declared for upcoming features.

[Unreleased]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/ag3ntsc4rn/anysoar/releases/tag/v0.0.1
