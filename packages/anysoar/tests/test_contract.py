"""The driver contract suite: run against the mock driver, and checked against bad drivers."""

import textwrap

import pytest
from pydantic import JsonValue

from anysoar.drivers.mock import MockDriver
from anysoar.testing import DriverContract


class TestMockDriverContract(DriverContract):
    @pytest.fixture
    def driver(self) -> MockDriver:
        return MockDriver()

    @pytest.fixture
    def case_uid(self) -> str:
        return "case-0002"

    @pytest.fixture
    def playbook_uid(self) -> str:
        return "pb-block-sender"

    @pytest.fixture
    def playbook_inputs(self) -> dict[str, JsonValue]:
        return {"sender": "billing@example.org"}


# The tests below run the suite in a separate pytest session (pytester) to check that it
# passes good drivers, skips what they don't support and fails bad ones. That session uses
# pytest-asyncio's default strict mode, as a third-party driver's test suite would.

PRELUDE = """
import pytest
from anysoar.drivers.mock import MockDriver
from anysoar.errors import NotFoundError
from anysoar.interface import AlertQuery, Driver, Page
from anysoar.models import DetectionFinding
from anysoar.testing import DriverContract
"""


def run_suite(pytester: pytest.Pytester, source: str) -> pytest.RunResult:
    pytester.makepyfile(test_driver=PRELUDE + source)
    return pytester.runpytest(
        "-p", "no:cacheprovider", "-o", "asyncio_default_fixture_loop_scope=function", "-rfs"
    )


def test_partial_driver_passes_with_skips(pytester: pytest.Pytester) -> None:
    result = run_suite(
        pytester,
        textwrap.dedent("""
        class AlertsOnly(Driver):
            name = "alerts-only"

            def __init__(self):
                self._mock = MockDriver()

            async def list_alerts(self, query=None):
                return await self._mock.list_alerts(query)

            async def get_alert(self, alert_uid):
                return await self._mock.get_alert(alert_uid)

        class TestAlertsOnly(DriverContract):
            @pytest.fixture
            def driver(self):
                return AlertsOnly()
        """),
    )
    outcomes = result.parseoutcomes()
    assert "failed" not in outcomes, result.stdout.str()
    # 3 discovery tests and 5 alert tests pass; the 11 others skip
    assert (outcomes["passed"], outcomes["skipped"]) == (8, 11)
    assert "driver does not support get_case" in result.stdout.str()


def test_missing_driver_fixture_fails(pytester: pytest.Pytester) -> None:
    result = run_suite(pytester, "class TestNothing(DriverContract): pass\n")
    result.assert_outcomes(errors=19, failed=0, passed=0)
    result.stdout.fnmatch_lines(["*must override the 'driver' fixture*"])


@pytest.mark.parametrize(
    ("override", "failing_test"),
    [
        pytest.param(
            """
            async def list_alerts(self, query=None):
                page = await super().list_alerts(query)
                return Page(items=page.items[::-1], next_cursor=page.next_cursor)
            """,
            "test_list_alerts",
            id="oldest-first",
        ),
        pytest.param(
            """
            async def list_alerts(self, query=None):
                query = query or AlertQuery()
                return await super().list_alerts(query.model_copy(update={"cursor": None}))
            """,
            "test_list_alerts_limit_and_cursor",
            id="cursor-ignored",
        ),
        pytest.param(
            """
            async def get_alert(self, alert_uid):
                try:
                    return await super().get_alert(alert_uid)
                except NotFoundError:
                    raise KeyError(alert_uid)
            """,
            "test_get_alert_not_found",
            id="vendor-exception-escapes",
        ),
        pytest.param(
            """
            async def get_case(self, case_uid):
                case = await super().get_case(case_uid)
                case.metadata.uid = "something-else"
                return case
            """,
            "test_get_case",
            id="case-uid-not-metadata-uid",
        ),
        pytest.param(
            """
            async def get_playbook_run(self, run_uid):
                run = await super().get_playbook_run(run_uid)
                return run.model_copy(update={"status": "running"})
            """,
            "test_run_playbook_until_finished",
            id="run-never-finishes",
        ),
    ],
)
def test_broken_driver_fails(pytester: pytest.Pytester, override: str, failing_test: str) -> None:
    broken = "class Broken(MockDriver):" + textwrap.indent(textwrap.dedent(override), "    ")
    result = run_suite(
        pytester,
        broken
        + textwrap.dedent("""
        class TestBroken(DriverContract):
            playbook_max_polls = 5

            @pytest.fixture
            def driver(self):
                return Broken()

            @pytest.fixture
            def case_uid(self):
                return "case-0002"

            @pytest.fixture
            def playbook_uid(self):
                return "pb-notify-reporter"
        """),
    )
    assert result.ret == pytest.ExitCode.TESTS_FAILED, result.stdout.str()
    assert f"FAILED test_driver.py::TestBroken::{failing_test} - " in result.stdout.str()
