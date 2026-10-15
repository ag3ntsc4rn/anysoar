# Contributing to anysoar

Thanks for your interest! anysoar is pre-alpha, so interfaces will change. Opening an issue
before starting larger work is the best way to avoid wasted effort.

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

### Packaging

Drivers live in `packages/anysoar/src/anysoar/drivers/<name>/` and ship as an optional
extra, `anysoar[<name>]`, so vendor dependencies stay out of the core install. (The mock
driver has no dependencies, so it has no extra.) Background on
the data model: [docs/adr/0001-ocsf-data-model.md](docs/adr/0001-ocsf-data-model.md).

If you'd like a driver for a particular SOAR, open a "New driver request" issue.
