"""The package README is the PyPI page: keep it true to what the package ships.

PyPI keeps each release's description, so a stale README stays wrong on that release's page
for good. These tests catch the mistakes that happened before: features called "planned"
after they shipped, links that only work inside the repository, and examples that rot.
"""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

PACKAGE = Path(__file__).parents[1]
README = (PACKAGE / "README.md").read_text()


def test_mentions_only_extras_that_exist() -> None:
    extras = tomllib.loads((PACKAGE / "pyproject.toml").read_text())["project"][
        "optional-dependencies"
    ]
    mentioned = set(re.findall(r"anysoar\[(\w+)\]", README))
    assert mentioned
    assert mentioned <= set(extras)


def test_no_stale_status() -> None:
    lowered = README.lower()
    for stale in ("(planned)", "reserves the package name", "no usable functionality"):
        assert stale not in lowered


def test_links_work_outside_the_repository() -> None:
    for target in re.findall(r"\]\(([^)]+)\)", README):
        assert target.startswith(("https://", "#")), f"relative link on PyPI: {target}"


def test_python_example_runs() -> None:
    (example,) = re.findall(r"```python\n(.*?)```", README, re.DOTALL)
    result = subprocess.run(
        [sys.executable, "-c", example], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "case-0002" in result.stdout
    assert "score_id" in result.stdout
