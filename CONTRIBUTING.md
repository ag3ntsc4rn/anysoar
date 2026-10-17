# Contributing to anysoar

Thanks for your interest! anysoar is pre-alpha, so interfaces can still change, but the
driver API changes only as described in
[Stability of the driver API](#stability-of-the-driver-api). Opening an issue before starting larger work is the best way to avoid wasted effort. If you
work for a SOAR vendor, [docs/for-vendors.md](docs/for-vendors.md) is a short overview.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.12+ (`uv python install 3.12` if you
don't have it).

```bash
git clone https://github.com/ag3ntsc4rn/anysoar.git
cd anysoar
uv sync                       # creates .venv with the package and dev tools
uv run pre-commit install     # runs lint, format, type checks and a secrets scan on commit
```

Day-to-day commands:

```bash
uv run pytest                 # tests
uv run ruff check --fix       # lint
uv run ruff format            # format
uv run mypy                   # type check (strict for packages/)
uv build --package anysoar    # build sdist and wheel into dist/
```

CI runs the same checks on every pull request.

## Branches and commits

- Branch from `main` and name it `<type>/<short-description>`, e.g. `feat/mock-driver`,
  `fix/case-pagination`, `docs/driver-guide`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Use `!` or a
  `BREAKING CHANGE:` footer for breaking changes.
- Keep pull requests small and focused. They are squash-merged, so the PR title becomes the
  commit message on `main` and should also follow Conventional Commits.
- Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## Signing off your commits

anysoar uses the [Developer Certificate of Origin](https://developercertificate.org) (DCO)
instead of a contributor licence agreement. By adding a `Signed-off-by` line to a commit you
certify that you wrote it, or otherwise have the right to submit it, under the project's
licence (Apache 2.0). `git commit -s` adds the line from your git name and email:

```
Signed-off-by: Your Name <you@example.com>
```

Every commit in a pull request needs one; a check on pull requests says which are missing.
To add it to commits you already made, run `git rebase --signoff main` and force-push the
branch. Contributions made on behalf of a company should be signed off by someone allowed to
make them; the DCO does not need a separate company agreement.

## Data and test fixtures

Use only public documentation and **synthetic** data. Never commit real alerts, logs,
indicators, credentials, customer data or anything from an employer or vendor that isn't
publicly available.

## Writing a driver

A driver connects anysoar to one SOAR platform. It subclasses `anysoar.interface.Driver`,
translates the SOAR's API to and from anysoar's OCSF-aligned models, and overrides only the
operations that SOAR supports.

### The contract

| Operation | Tier | Returns |
|---|---|---|
| `list_alerts(query)` | read | `Page[DetectionFinding]`, newest first |
| `get_alert(alert_uid)` | read | `DetectionFinding` |
| `list_cases(query)` | read | `Page[IncidentFinding]`, most recently updated first |
| `get_case(case_uid)` | read | `IncidentFinding` |
| `add_note(case_uid, note)` | write | the stored `Note` |
| `close_case(case_uid, verdict_id=..., comment=...)` | write | the updated `IncidentFinding` |
| `enrich_indicator(indicator)` | read | `IndicatorEnrichment` |
| `list_playbooks()` | read | `list[Playbook]` |
| `run_playbook(playbook_uid, case_uid=..., alert_uid=..., inputs=...)` | write or higher | `PlaybookRun` (returns immediately) |
| `get_playbook_run(run_uid)` | read | `PlaybookRun` |

All operations are `async`. Each corresponds to a `Capability`, and its tier is listed in
`CAPABILITY_TIERS`. Tiers are enforced by the policy layer, not by drivers.

### Rules

1. **Capabilities are the methods you override.** Don't stub operations your SOAR can't do;
   leave them out and the base class raises `CapabilityNotSupportedError`. If support
   depends on the SOAR version or API permissions, override `describe()` and return a
   subset of `implemented_capabilities()`, never a superset.
2. **Speak OCSF.** Map native fields to the models in `anysoar.models`. Put native values
   that have no OCSF home in `unmapped` and keep the model valid. Never add fields to the
   models for one vendor. Alert uids are `finding_info.uid`; case uids are `metadata.uid`,
   because an OCSF Incident Finding has no uid of its own.
3. **Use the error types.** Raise `NotFoundError` for missing objects and `DriverError` for
   SOAR or network failures (set `retryable=True` for timeouts and rate limits). Don't let
   vendor SDK or HTTP exceptions escape.
4. **Declare playbook risk.** Set `Playbook.tier` to `DESTRUCTIVE` for playbooks that do
   irreversible things (deleting data, disabling accounts, isolating hosts). If you can't
   tell, keep the default `WRITE` and document it.
5. **Release resources in `aclose()`.** Drivers are used as async context managers.
6. **Test with synthetic data only.** Use recorded or hand-written responses with
   `example.com` domains and documentation IP ranges (RFC 5737), never real alerts.

### Skeleton

```python
from anysoar.errors import NotFoundError
from anysoar.interface import AlertQuery, Driver, Page
from anysoar.models import DetectionFinding


class ExampleDriver(Driver):
    name = "example"

    def __init__(self, base_url: str, api_key: str) -> None:
        self._client = ExampleClient(base_url, api_key)  # your HTTP client

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        query = query or AlertQuery()
        raw = await self._client.alerts(limit=query.limit, cursor=query.cursor)
        return Page(items=[to_alert(a) for a in raw["items"]], next_cursor=raw.get("next"))

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        raw = await self._client.alert(alert_uid)
        if raw is None:
            raise NotFoundError("alert", alert_uid)
        return to_alert(raw)

    async def aclose(self) -> None:
        await self._client.close()
```

`ExampleDriver.implemented_capabilities()` is `{LIST_ALERTS, GET_ALERT}`, and agents will only
be offered those operations.

### Testing your driver

Every driver must pass the contract suite in `anysoar.testing` (install the `testing` extra,
`pip install "anysoar[testing]"`). Subclass `DriverContract` in a test module and override
its fixtures:

```python
import pytest

from anysoar.testing import DriverContract


class TestExampleDriver(DriverContract):
    @pytest.fixture
    def driver(self) -> ExampleDriver:
        return ExampleDriver(transport=recorded_responses())  # never a production SOAR

    @pytest.fixture
    def case_uid(self) -> str:
        return "case-1"  # an open case; needed only if you support case operations
```

The suite checks capability discovery, alert ordering, paging and filters, that findings are
valid OCSF, case uids, notes, closing, enrichment, playbook runs reaching a final state, and
`NotFoundError` handling. Tests for capabilities your driver doesn't report are skipped. Each
test gets a fresh `driver`, and some tests write to it. Other fixtures you can override:
`alert_uid`, `indicator`, `playbook_uid` and `playbook_inputs`. For slow SOARs you can also
set the class attributes `playbook_poll_interval` and `playbook_max_polls`. Add your own tests
for behaviour specific to your SOAR alongside the suite.

`anysoar.drivers.mock` is a complete reference implementation that passes the suite.
`anysoar.drivers.shuffle` shows a driver for a real SOAR: an HTTP client that maps the SOAR's
error responses to anysoar's errors, translation of a vendor's near-OCSF records, the
contract suite run against an in-process fake built from captured responses, and the same
suite run against a live instance behind an opt-in environment variable
(`ANYSOAR_LIVE_SHUFFLE=1`). `anysoar.drivers.tines` follows the same pattern for a SaaS
SOAR (`ANYSOAR_LIVE_TINES=1`). `anysoar.drivers.thehive` covers alerts and enrichment too,
and its live suite (`ANYSOAR_LIVE_THEHIVE=1`) creates the alerts and cases it tests with
and deletes them afterwards.

### Stability of the driver API

The driver API is what a driver is written and tested against:

- `anysoar.interface`: `Driver`, `Capability`, `ActionTier` and the query, page and playbook
  types;
- `anysoar.models` and `anysoar.errors`;
- `anysoar.testing.DriverContract`;
- the `anysoar.drivers` entry point group, `available_drivers()`, `create_driver()` and
  `Retry`.

Until 1.0, anysoar follows these rules for it:

- **Breaking changes only in minor releases** (0.6 to 0.7), never in patch releases
  (0.6.0 to 0.6.1). Each is listed in the changelog under "Changed" or "Removed" with what
  to do instead.
- **Deprecation first where practical:** the old way keeps working, with a
  `DeprecationWarning`, for at least one minor release.
- **Additions are not breaking.** A new capability is a new `Driver` method that raises
  `CapabilityNotSupportedError` by default, so existing drivers keep working and the
  contract suite skips it for them. New optional fields work the same way.

So a driver in its own package should depend on the minor release it is tested against
(e.g. `anysoar>=0.6,<0.7`) and raise the bound after checking each new minor release; the
changelog says what changed. From 1.0 on, breaking changes need a major release.

### Packaging

A driver can live here or in its own package.

**Here (built in).** Drivers live in `packages/anysoar/src/anysoar/drivers/<name>/` and ship
as an optional extra, `anysoar[<name>]`, so vendor dependencies stay out of the core
install. (The mock driver has no dependencies, so it has no extra.) The maintainers keep
them working.

**In your own package.** Publish a package (by convention `anysoar-<name>`) that depends on
`anysoar` and declares your driver in the `anysoar.drivers` entry point group:

```toml
[project]
name = "anysoar-acme"
dependencies = ["anysoar>=0.6,<0.7"]  # the minor release you test against; see below

[project.entry-points."anysoar.drivers"]
acme = "anysoar_acme:AcmeDriver"
```

Once it is installed, `anysoar-mcp --driver acme` starts it, and
`anysoar.drivers.create_driver("acme")` does the same from Python. The driver is created
with no arguments, so read settings from environment variables (e.g. `ACME_URL`,
`ACME_API_KEY`) as the built-in drivers do. A package cannot take the name of a built-in
driver. You release and maintain it yourself; run `DriverContract` against a real instance
in your CI, and open an issue to have it listed in the README's driver table as
vendor-maintained or community.

Background on
the data model: [docs/adr/0001-ocsf-data-model.md](docs/adr/0001-ocsf-data-model.md); on
how tiers are enforced: [docs/adr/0002-policy-layer.md](docs/adr/0002-policy-layer.md).

If you'd like a driver for a particular SOAR, open a "New driver request" issue.
