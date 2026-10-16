# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- The `shuffle` extra now depends on `httpx2` (used by the MCP and Anthropic SDKs) instead of
  `httpx`.

## [0.0.1] - 2026-10-15

### Added

- Initial package skeleton exposing `anysoar.__version__`, published to reserve the name.
- Optional extras `mcp` and `shuffle` declared for upcoming features.

[Unreleased]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/ag3ntsc4rn/anysoar/releases/tag/v0.0.1
