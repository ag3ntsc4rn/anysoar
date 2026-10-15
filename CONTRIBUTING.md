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

> The driver interface lands in roadmap phase 1. This section will document it once it exists.

In outline, a driver will:

1. Implement the driver contract in `anysoar.interface`.
2. Translate between the SOAR's native API and anysoar's OCSF-aligned models.
3. Report its capabilities so agents can discover what the underlying SOAR supports.
4. Ship as an optional extra (`anysoar[<vendor>]`) with its own tests against recorded or
   synthetic responses.

If you'd like a driver for a particular SOAR, open a "New driver request" issue.
