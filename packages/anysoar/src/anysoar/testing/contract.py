"""The driver contract test suite: behaviour every anysoar driver must show.

Subclass :class:`DriverContract` in a test module (its name must start with ``Test``) and
override the ``driver`` fixture::

    import pytest
    from anysoar.testing import DriverContract

    class TestExampleDriver(DriverContract):
        @pytest.fixture
        def driver(self) -> ExampleDriver:
            return ExampleDriver(base_url="https://soar.example.com", api_key="test")

        @pytest.fixture
        def case_uid(self) -> str:
            return "case-1"

Each test gets a fresh ``driver``, and write tests change its state, so point it at a fake,
a recorded-response transport or a disposable SOAR instance, never production. Tests for
capabilities the driver does not report in :meth:`~anysoar.interface.Driver.describe` are
skipped; capabilities it does not implement must raise
:class:`~anysoar.errors.CapabilityNotSupportedError`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import ClassVar

from pydantic import JsonValue

from anysoar._extras import missing_extra

try:
    import pytest
    import pytest_asyncio
except ModuleNotFoundError as exc:
    raise missing_extra("testing", exc) from exc

from anysoar.errors import CapabilityNotSupportedError, NotFoundError
from anysoar.interface import (
    ActionTier,
    AlertQuery,
    Capability,
    CaseQuery,
    Driver,
    DriverInfo,
    IndicatorEnrichment,
    Playbook,
    PlaybookRun,
)
from anysoar.models import (
    DetectionFinding,
    IncidentFinding,
    IncidentFindingStatusId,
    Note,
    Observable,
    ObservableTypeId,
    SeverityId,
    VerdictId,
)

__all__ = ["DriverContract"]


def _created(alert: DetectionFinding) -> int:
    created = alert.finding_info.created_time
    return created if created is not None else alert.time


def _assert_valid_alert(alert: object) -> None:
    assert isinstance(alert, DetectionFinding), f"expected a DetectionFinding, got {alert!r}"
    assert DetectionFinding.from_ocsf(alert.to_ocsf()) == alert, "alert does not round-trip"


def _assert_valid_case(case: object) -> None:
    assert isinstance(case, IncidentFinding), f"expected an IncidentFinding, got {case!r}"
    assert IncidentFinding.from_ocsf(case.to_ocsf()) == case, "case does not round-trip"


_UNSUPPORTED_CALLS: dict[Capability, Callable[[Driver], Awaitable[object]]] = {
    Capability.LIST_ALERTS: lambda d: d.list_alerts(),
    Capability.GET_ALERT: lambda d: d.get_alert("x"),
    Capability.LIST_CASES: lambda d: d.list_cases(),
    Capability.GET_CASE: lambda d: d.get_case("x"),
    Capability.ADD_NOTE: lambda d: d.add_note("x", Note(comment="x")),
    Capability.CLOSE_CASE: lambda d: d.close_case("x", verdict_id=VerdictId.BENIGN),
    Capability.ENRICH_INDICATOR: lambda d: d.enrich_indicator(
        Observable(type_id=ObservableTypeId.IP_ADDRESS, value="192.0.2.1")
    ),
    Capability.LIST_PLAYBOOKS: lambda d: d.list_playbooks(),
    Capability.RUN_PLAYBOOK: lambda d: d.run_playbook("x"),
    Capability.GET_PLAYBOOK_RUN: lambda d: d.get_playbook_run("x"),
}


_CASE_CAPABILITIES = frozenset({Capability.GET_CASE, Capability.ADD_NOTE, Capability.CLOSE_CASE})


class DriverContract:
    """Base class of the contract tests. See the module docstring for usage.

    Fixtures to override:

    - ``driver`` (required): a fresh driver instance; sync or async, may ``yield``.
    - ``case_uid``: an open case; required if the driver supports case operations.
    - ``alert_uid``: an existing alert; defaults to the newest from ``list_alerts``.
    - ``indicator``: an observable to enrich; defaults to a documentation IP address.
    - ``playbook_uid`` and ``playbook_inputs``: a playbook that is safe to run and its
      inputs; defaults to the first ``WRITE`` tier playbook with no inputs.
    """

    pytestmark: ClassVar[list[pytest.MarkDecorator]] = [pytest.mark.asyncio]

    missing_uid: ClassVar[str] = "anysoar-contract-missing-uid"
    """A uid that matches no alert, case, playbook or run."""
    playbook_poll_interval: ClassVar[float] = 0.0
    """Seconds to wait between polls of a playbook run."""
    playbook_max_polls: ClassVar[int] = 100
    """Polls to wait for a playbook run to finish before failing."""

    # -- Fixtures -------------------------------------------------------------------------

    @pytest.fixture
    def driver(self) -> Driver:
        pytest.fail(f"{type(self).__name__} must override the 'driver' fixture")

    @pytest_asyncio.fixture
    async def info(self, driver: Driver) -> DriverInfo:
        return await driver.describe()

    @pytest.fixture
    def case_uid(self, info: DriverInfo) -> str:
        if not info.capabilities & _CASE_CAPABILITIES:
            pytest.skip("driver does not support case operations")
        pytest.fail(f"{type(self).__name__} must override the 'case_uid' fixture")

    @pytest_asyncio.fixture
    async def alert_uid(self, driver: Driver, info: DriverInfo) -> str:
        self.require(info, Capability.GET_ALERT)
        if Capability.LIST_ALERTS not in info.capabilities:
            pytest.fail(f"{type(self).__name__} must override the 'alert_uid' fixture")
        page = await driver.list_alerts(AlertQuery(limit=1))
        if not page.items:
            pytest.skip("the driver has no alerts to test with")
        return page.items[0].finding_info.uid

    @pytest.fixture
    def indicator(self) -> Observable:
        return Observable(type_id=ObservableTypeId.IP_ADDRESS, value="192.0.2.1")

    @pytest_asyncio.fixture
    async def playbook_uid(self, driver: Driver, info: DriverInfo) -> str:
        self.require(info, Capability.RUN_PLAYBOOK)
        if Capability.LIST_PLAYBOOKS not in info.capabilities:
            pytest.fail(f"{type(self).__name__} must override the 'playbook_uid' fixture")
        for playbook in await driver.list_playbooks():
            if playbook.tier is ActionTier.WRITE:
                return playbook.uid
        pytest.skip("the driver has no write-tier playbook to test with")

    @pytest.fixture
    def playbook_inputs(self) -> dict[str, JsonValue]:
        return {}

    # -- Helpers --------------------------------------------------------------------------

    @staticmethod
    def require(info: DriverInfo, *capabilities: Capability) -> None:
        """Skip the test unless the driver reports all of ``capabilities``."""
        missing = [c.value for c in capabilities if c not in info.capabilities]
        if missing:
            pytest.skip(f"driver does not support {', '.join(missing)}")

    async def all_alerts(self, driver: Driver, query: AlertQuery | None = None) -> list[str]:
        """Uids of every alert matching ``query``, following cursors (at most 50 pages)."""
        query = query or AlertQuery(limit=500)
        uids: list[str] = []
        for _ in range(50):
            page = await driver.list_alerts(query)
            uids += [a.finding_info.uid for a in page.items]
            if page.next_cursor is None:
                return uids
            query = query.model_copy(update={"cursor": page.next_cursor})
        return uids

    # -- Discovery ------------------------------------------------------------------------

    async def test_describe(self, driver: Driver, info: DriverInfo) -> None:
        assert isinstance(info, DriverInfo)
        assert info.name == driver.name
        extra = info.capabilities - type(driver).implemented_capabilities()
        assert not extra, f"describe() claims unimplemented capabilities: {sorted(extra)}"

    async def test_unimplemented_capabilities_raise(self, driver: Driver) -> None:
        for capability in set(Capability) - type(driver).implemented_capabilities():
            with pytest.raises(CapabilityNotSupportedError) as raised:
                await _UNSUPPORTED_CALLS[capability](driver)
            assert raised.value.capability is capability, capability.value

    async def test_aclose_is_idempotent(self, driver: Driver) -> None:
        await driver.aclose()
        await driver.aclose()

    # -- Alerts ---------------------------------------------------------------------------

    async def test_list_alerts(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_ALERTS)
        page = await driver.list_alerts()
        for alert in page.items:
            _assert_valid_alert(alert)
        created = [_created(a) for a in page.items]
        assert created == sorted(created, reverse=True), "alerts are not newest first"

    async def test_list_alerts_limit_and_cursor(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_ALERTS)
        everything = await self.all_alerts(driver)
        if len(everything) < 2:
            pytest.skip("need at least two alerts to test paging")
        first = await driver.list_alerts(AlertQuery(limit=1))
        assert len(first.items) == 1
        assert first.next_cursor is not None, "more alerts exist but next_cursor is None"
        paged = await self.all_alerts(driver, AlertQuery(limit=1))
        assert len(paged) == len(set(paged)), "paging returned an alert twice"
        assert paged == everything[: len(paged)], "paging and one big page disagree"

    async def test_list_alerts_filters(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_ALERTS)
        page = await driver.list_alerts()
        if not page.items:
            pytest.skip("the driver has no alerts to test with")
        sample = page.items[0]
        uid, created = sample.finding_info.uid, _created(sample)

        if sample.status_id is not None:
            query = AlertQuery(status_ids=frozenset({sample.status_id}))
            matched = (await driver.list_alerts(query)).items
            assert uid in {a.finding_info.uid for a in matched}
            assert all(a.status_id == sample.status_id for a in matched)

        if sample.severity_id not in (SeverityId.UNKNOWN, SeverityId.OTHER):
            matched = (
                await driver.list_alerts(AlertQuery(min_severity_id=sample.severity_id))
            ).items
            assert uid in {a.finding_info.uid for a in matched}
            assert all(sample.severity_id <= a.severity_id != SeverityId.OTHER for a in matched)

        since = (await driver.list_alerts(AlertQuery(since=created))).items
        assert uid in {a.finding_info.uid for a in since}
        assert all(_created(a) >= created for a in since)
        until = (await driver.list_alerts(AlertQuery(until=created))).items
        assert uid not in {a.finding_info.uid for a in until}
        assert all(_created(a) < created for a in until)

    async def test_get_alert(self, driver: Driver, info: DriverInfo, alert_uid: str) -> None:
        self.require(info, Capability.GET_ALERT)
        alert = await driver.get_alert(alert_uid)
        _assert_valid_alert(alert)
        assert alert.finding_info.uid == alert_uid

    async def test_get_alert_not_found(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.GET_ALERT)
        with pytest.raises(NotFoundError):
            await driver.get_alert(self.missing_uid)

    # -- Cases ----------------------------------------------------------------------------

    async def all_cases(self, driver: Driver, query: CaseQuery | None = None) -> list[str]:
        """Uids of every case matching ``query``, following cursors (at most 50 pages)."""
        query = query or CaseQuery(limit=500)
        uids: list[str] = []
        for _ in range(50):
            page = await driver.list_cases(query)
            uids += [c.metadata.uid or "" for c in page.items]
            if page.next_cursor is None:
                return uids
            query = query.model_copy(update={"cursor": page.next_cursor})
        return uids

    async def test_list_cases(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_CASES)
        page = await driver.list_cases()
        for case in page.items:
            _assert_valid_case(case)
            assert case.metadata.uid, "a listed case has no metadata.uid"
        times = [c.time for c in page.items]
        assert times == sorted(times, reverse=True), "cases are not most recently updated first"

    async def test_list_cases_limit_and_cursor(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_CASES)
        everything = await self.all_cases(driver)
        if len(everything) < 2:
            pytest.skip("need at least two cases to test paging")
        first = await driver.list_cases(CaseQuery(limit=1))
        assert len(first.items) == 1
        assert first.next_cursor is not None, "more cases exist but next_cursor is None"
        paged = await self.all_cases(driver, CaseQuery(limit=1))
        assert len(paged) == len(set(paged)), "paging returned a case twice"
        assert paged == everything[: len(paged)], "paging and one big page disagree"

    async def test_list_cases_status_filter(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_CASES)
        page = await driver.list_cases()
        if not page.items:
            pytest.skip("the driver has no cases to test with")
        sample = page.items[0]
        matched = (
            await driver.list_cases(CaseQuery(status_ids=frozenset({sample.status_id})))
        ).items
        assert sample.metadata.uid in {c.metadata.uid for c in matched}
        assert all(c.status_id == sample.status_id for c in matched)

    async def test_get_case(self, driver: Driver, info: DriverInfo, case_uid: str) -> None:
        self.require(info, Capability.GET_CASE)
        case = await driver.get_case(case_uid)
        _assert_valid_case(case)
        assert case.metadata.uid == case_uid, "a case's uid must be its metadata.uid"

    async def test_add_note(self, driver: Driver, info: DriverInfo, case_uid: str) -> None:
        self.require(info, Capability.ADD_NOTE)
        comment = "anysoar contract test note"
        stored = await driver.add_note(case_uid, Note(comment=comment))
        assert isinstance(stored, Note)
        assert stored.comment == comment
        if Capability.GET_CASE in info.capabilities:
            notes = (await driver.get_case(case_uid)).notes
            assert any(n.comment == comment for n in notes), "note is not on the case"

    async def test_close_case(self, driver: Driver, info: DriverInfo, case_uid: str) -> None:
        self.require(info, Capability.CLOSE_CASE)
        closed_states = {IncidentFindingStatusId.RESOLVED, IncidentFindingStatusId.CLOSED}
        case = await driver.close_case(
            case_uid, verdict_id=VerdictId.FALSE_POSITIVE, comment="anysoar contract test"
        )
        _assert_valid_case(case)
        assert case.status_id in closed_states
        assert case.verdict_id is VerdictId.FALSE_POSITIVE
        if Capability.GET_CASE in info.capabilities:
            fetched = await driver.get_case(case_uid)
            assert fetched.status_id in closed_states
            assert fetched.verdict_id is VerdictId.FALSE_POSITIVE

    @pytest.mark.parametrize(
        "capability",
        [Capability.GET_CASE, Capability.ADD_NOTE, Capability.CLOSE_CASE],
        ids=lambda c: c.value,
    )
    async def test_case_not_found(
        self, driver: Driver, info: DriverInfo, capability: Capability
    ) -> None:
        self.require(info, capability)
        with pytest.raises(NotFoundError):
            if capability is Capability.GET_CASE:
                await driver.get_case(self.missing_uid)
            elif capability is Capability.ADD_NOTE:
                await driver.add_note(self.missing_uid, Note(comment="x"))
            else:
                await driver.close_case(self.missing_uid, verdict_id=VerdictId.BENIGN)

    # -- Indicators -----------------------------------------------------------------------

    async def test_enrich_indicator(
        self, driver: Driver, info: DriverInfo, indicator: Observable
    ) -> None:
        self.require(info, Capability.ENRICH_INDICATOR)
        result = await driver.enrich_indicator(indicator)
        assert isinstance(result, IndicatorEnrichment)
        assert result.observable.type_id == indicator.type_id
        assert result.observable.value == indicator.value

    # -- Playbooks ------------------------------------------------------------------------

    async def test_list_playbooks(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.LIST_PLAYBOOKS)
        playbooks = await driver.list_playbooks()
        assert all(isinstance(p, Playbook) for p in playbooks)
        uids = [p.uid for p in playbooks]
        assert len(uids) == len(set(uids)), "playbook uids are not unique"

    async def test_run_playbook_until_finished(
        self,
        driver: Driver,
        info: DriverInfo,
        playbook_uid: str,
        playbook_inputs: dict[str, JsonValue],
    ) -> None:
        self.require(info, Capability.RUN_PLAYBOOK, Capability.GET_PLAYBOOK_RUN)
        run = await driver.run_playbook(playbook_uid, inputs=playbook_inputs)
        assert isinstance(run, PlaybookRun)
        assert run.playbook_uid == playbook_uid
        for _ in range(self.playbook_max_polls):
            if run.status.is_finished:
                break
            await asyncio.sleep(self.playbook_poll_interval)
            polled = await driver.get_playbook_run(run.uid)
            assert (polled.uid, polled.playbook_uid) == (run.uid, playbook_uid)
            run = polled
        else:
            pytest.fail(f"run {run.uid} did not finish in {self.playbook_max_polls} polls")
        assert (await driver.get_playbook_run(run.uid)).status is run.status, (
            "a finished run changed status"
        )

    async def test_run_playbook_not_found(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.RUN_PLAYBOOK)
        with pytest.raises(NotFoundError):
            await driver.run_playbook(self.missing_uid)

    async def test_get_playbook_run_not_found(self, driver: Driver, info: DriverInfo) -> None:
        self.require(info, Capability.GET_PLAYBOOK_RUN)
        with pytest.raises(NotFoundError):
            await driver.get_playbook_run(self.missing_uid)
