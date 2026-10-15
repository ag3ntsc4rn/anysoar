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

## [0.0.1] - 2026-10-15

### Added

- Initial package skeleton exposing `anysoar.__version__`, published to reserve the name.
- Optional extras `mcp` and `shuffle` declared for upcoming features.

[Unreleased]: https://github.com/ag3ntsc4rn/anysoar/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/ag3ntsc4rn/anysoar/releases/tag/v0.0.1
