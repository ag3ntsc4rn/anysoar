import json
import os
import uuid
from collections.abc import AsyncIterator

import httpx2
import pytest
import pytest_asyncio

from anysoar.drivers.thehive import TheHiveDriver
from anysoar.drivers.thehive.alerts import alert_status_filter, min_severity, to_alert
from anysoar.drivers.thehive.client import TheHiveAPIError
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import AlertQuery, Capability
from anysoar.models import (
    DetectionFindingStatusId,
    Observable,
    ObservableTypeId,
    SeverityId,
    User,
    VerdictId,
)
from anysoar.testing import DriverContract

from .. import NO_WAIT
from .fake_thehive import API_KEY, BASE_URL, MINUTE, T0, FakeTheHive

Status = DetectionFindingStatusId


@pytest.fixture
def thehive() -> FakeTheHive:
    return FakeTheHive()


@pytest.fixture
def soar(thehive: FakeTheHive) -> TheHiveDriver:
    return TheHiveDriver(BASE_URL, API_KEY, retry=NO_WAIT, transport=thehive.transport())


class TestTheHiveContract(DriverContract):
    @pytest.fixture
    def fake(self) -> FakeTheHive:
        return FakeTheHive()

    @pytest.fixture
    def driver(self, fake: FakeTheHive) -> TheHiveDriver:
        return TheHiveDriver(BASE_URL, API_KEY, retry=NO_WAIT, transport=fake.transport())

    @pytest.fixture
    def case_uid(self, fake: FakeTheHive) -> str:
        return fake.open_case


class TestConfiguration:
    async def test_describe(self, soar: TheHiveDriver) -> None:
        info = await soar.describe()
        assert info.name == "thehive"
        assert (info.soar_product, info.soar_version) == ("TheHive", "5.8.1-1")
        assert info.capabilities == {
            Capability.LIST_ALERTS,
            Capability.GET_ALERT,
            Capability.LIST_CASES,
            Capability.GET_CASE,
            Capability.ADD_NOTE,
            Capability.CLOSE_CASE,
            Capability.ENRICH_INDICATOR,
        }

    def test_reads_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THEHIVE_URL", BASE_URL)
        monkeypatch.setenv("THEHIVE_API_KEY", API_KEY)
        monkeypatch.setenv("THEHIVE_ORGANISATION", "soc")
        assert TheHiveDriver()._client._http.headers["X-Organisation"] == "soc"

    def test_needs_url_and_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("THEHIVE_URL", raising=False)
        monkeypatch.delenv("THEHIVE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="THEHIVE_URL"):
            TheHiveDriver()

    async def test_bad_key(self, thehive: FakeTheHive) -> None:
        soar = TheHiveDriver(BASE_URL, "wrong", retry=NO_WAIT, transport=thehive.transport())
        with pytest.raises(TheHiveAPIError) as error:
            await soar.list_alerts()
        assert error.value.status == 401
        assert error.value.kind == "AuthenticationError"
        assert not error.value.retryable

    async def test_unreachable(self) -> None:
        def refuse(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused", request=request)

        soar = TheHiveDriver(
            BASE_URL, API_KEY, retry=NO_WAIT, transport=httpx2.MockTransport(refuse)
        )
        with pytest.raises(DriverError, match="Could not reach TheHive") as error:
            await soar.list_alerts()
        assert error.value.retryable
        info = await soar.describe()  # still describes itself, without a version
        assert info.soar_version is None


class TestReadingAlerts:
    async def test_alert(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        alert = await soar.get_alert(thehive.phishing)
        assert alert.finding_info.uid == alert.metadata.uid == thehive.phishing
        assert alert.metadata.product.name == "TheHive"
        assert alert.message == alert.finding_info.title
        assert alert.finding_info.title == "Reported phishing: invoice from it-support@example.net"
        assert alert.severity_id is SeverityId.HIGH
        assert (alert.status_id, alert.status) == (Status.NEW, "New")
        assert alert.verdict_id is None
        assert alert.is_alert
        info = alert.finding_info
        assert info.created_time == T0 + 30 * MINUTE
        assert info.first_seen_time == T0 + 28 * MINUTE  # when the source raised it
        assert alert.time == info.modified_time == T0 + 31 * MINUTE
        assert info.types == ["external", "phishing"]
        assert info.src_url == f"https://gateway.example.com/events/{thehive.phishing[1:]}"
        assert alert.unmapped is not None
        assert alert.unmapped["source"] == "mail-gateway"

    async def test_alert_observables(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        alert = await soar.get_alert(thehive.phishing)
        assert [(o.type_id, o.type, o.value) for o in alert.observables] == [
            (ObservableTypeId.EMAIL_ADDRESS, "mail", "it-support@example.net"),
            (ObservableTypeId.URL_STRING, "url", "https://login.example.org/invoice"),
            (ObservableTypeId.IP_ADDRESS, "ip", "198.51.100.23"),
        ]

    async def test_assignee(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        alert = await soar.get_alert(thehive.triaging)
        assert alert.assignee == User(
            uid="robin@example.com", name="robin@example.com", email_addr="robin@example.com"
        )

    @pytest.mark.parametrize(
        ("status", "stage", "ocsf", "verdict"),
        [
            ("New", "New", Status.NEW, None),
            ("InProgress", "InProgress", Status.IN_PROGRESS, None),
            ("Pending", "InProgress", Status.IN_PROGRESS, None),
            ("Imported", "Imported", Status.OTHER, None),
            ("FalsePositive", "Closed", Status.RESOLVED, VerdictId.FALSE_POSITIVE),
            ("Duplicate", "Closed", Status.RESOLVED, VerdictId.DUPLICATE),
            ("Ignored", "Closed", Status.SUPPRESSED, None),
            ("Escalated", "Closed", Status.RESOLVED, None),  # a custom closing status
        ],
    )
    def test_status_mapping(
        self, status: str, stage: str, ocsf: Status, verdict: VerdictId | None
    ) -> None:
        alert = to_alert({"_id": "~1", "_createdAt": T0, "status": status, "stage": stage})
        assert (alert.status_id, alert.status, alert.verdict_id) == (ocsf, status, verdict)

    @pytest.mark.parametrize(
        ("data_type", "ocsf"),
        [
            ("domain", ObservableTypeId.HOSTNAME),
            ("fqdn", ObservableTypeId.HOSTNAME),
            ("hash", ObservableTypeId.HASH),
            ("user-agent", ObservableTypeId.HTTP_USER_AGENT),
            ("autonomous-system", ObservableTypeId.OTHER),
        ],
    )
    def test_observable_types(self, data_type: str, ocsf: ObservableTypeId) -> None:
        record = {"_id": "~1", "_createdAt": T0}
        (observable,) = to_alert(record, [{"dataType": data_type, "data": "x"}]).observables
        assert (observable.type_id, observable.type) == (ocsf, data_type)

    def test_minimal_alert(self) -> None:
        alert = to_alert({"_id": "~1", "_createdAt": T0})
        assert alert.severity_id is SeverityId.UNKNOWN
        assert alert.time == T0
        assert alert.unmapped is None

    async def test_not_found(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        with pytest.raises(NotFoundError):
            await soar.get_alert("~1")
        requests = len(thehive.requests)
        with pytest.raises(NotFoundError):
            await soar.get_alert("8200")  # not a TheHive id: TheHive is not asked
        assert len(thehive.requests) == requests


class TestListingAlerts:
    async def test_newest_first_without_observables(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        page = await soar.list_alerts()
        assert [a.finding_info.uid for a in page.items] == [
            thehive.phishing,
            thehive.scan,
            thehive.triaging,
            thehive.dismissed,
            thehive.false_alarm,
            thehive.imported,
        ]
        assert all(a.observables == [] for a in page.items)  # get_alert fetches them
        assert page.next_cursor is None

    async def test_paging(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        first = await soar.list_alerts(AlertQuery(limit=2))
        assert [a.finding_info.uid for a in first.items] == [thehive.phishing, thehive.scan]
        assert first.next_cursor == "2"
        last = await soar.list_alerts(AlertQuery(limit=4, cursor=first.next_cursor))
        assert len(last.items) == 4
        assert last.next_cursor is None

    async def test_invalid_cursor(self, soar: TheHiveDriver) -> None:
        with pytest.raises(DriverError, match="cursor"):
            await soar.list_alerts(AlertQuery(cursor="next"))

    @pytest.mark.parametrize(
        ("statuses", "expected"),
        [
            ({Status.NEW}, ["phishing", "scan"]),
            ({Status.IN_PROGRESS}, ["triaging"]),
            ({Status.SUPPRESSED}, ["dismissed"]),
            ({Status.RESOLVED}, ["false_alarm"]),
            ({Status.NEW, Status.SUPPRESSED}, ["phishing", "scan", "dismissed"]),
            ({Status.OTHER}, ["imported"]),
            ({Status.ARCHIVED}, []),
        ],
    )
    async def test_status_filter(
        self,
        soar: TheHiveDriver,
        thehive: FakeTheHive,
        statuses: set[Status],
        expected: list[str],
    ) -> None:
        page = await soar.list_alerts(AlertQuery(status_ids=frozenset(statuses)))
        assert [a.finding_info.uid for a in page.items] == [getattr(thehive, n) for n in expected]

    async def test_filters_go_to_thehive(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        since, until = T0 + 10 * MINUTE, T0 + 30 * MINUTE
        query = AlertQuery(min_severity_id=SeverityId.MEDIUM, since=since, until=until)
        page = await soar.list_alerts(query)
        assert [a.finding_info.uid for a in page.items] == [thehive.triaging]
        sent = json.loads(thehive.requests[-1].content)["query"]
        assert sent[1] == {
            "_name": "filter",
            "_and": [
                {"_gte": {"_field": "severity", "_value": 2}},
                {"_gte": {"_field": "_createdAt", "_value": since}},
                {"_lt": {"_field": "_createdAt", "_value": until}},
            ],
        }

    @pytest.mark.parametrize(
        ("ocsf", "thehive_severity"),
        [
            (SeverityId.UNKNOWN, 1),
            (SeverityId.INFORMATIONAL, 1),
            (SeverityId.LOW, 1),
            (SeverityId.MEDIUM, 2),
            (SeverityId.CRITICAL, 4),
            (SeverityId.FATAL, 5),  # matches nothing
        ],
    )
    def test_min_severity(self, ocsf: SeverityId, thehive_severity: int) -> None:
        assert min_severity(ocsf) == thehive_severity

    def test_status_filter_for_one_status_is_not_wrapped(self) -> None:
        assert alert_status_filter(frozenset({Status.NEW})) == {
            "_eq": {"_field": "stage", "_value": "New"}
        }


live = pytest.mark.skipif(
    os.environ.get("ANYSOAR_LIVE_THEHIVE") != "1",
    reason="needs a TheHive instance such as demo/thehive; set ANYSOAR_LIVE_THEHIVE=1, "
    "THEHIVE_URL and THEHIVE_API_KEY",
)


@live
class TestLiveTheHiveContract(DriverContract):
    """The contract suite against a real TheHive. Creates synthetic alerts and cases, and
    deletes them afterwards."""

    @pytest_asyncio.fixture
    async def lab(self) -> AsyncIterator[dict[str, list[str]]]:
        """Two alerts and two cases, made over a connection of their own: tests close the
        driver they are given. Yields their alert ids and case numbers."""
        async with TheHiveDriver() as setup:
            created: dict[str, list[str]] = {"alert": [], "case": []}
            try:
                for n, severity in enumerate((2, 3)):
                    alert = await setup._client.request(
                        "POST",
                        "/api/v1/alert",
                        json={
                            "type": "anysoar-contract",
                            "source": "anysoar",
                            "sourceRef": f"contract-{uuid.uuid4().hex}",
                            "title": f"anysoar contract test alert {n}",
                            "description": "Synthetic alert created by anysoar's contract tests.",
                            "severity": severity,
                            "observables": [{"dataType": "ip", "data": f"192.0.2.{n + 1}"}],
                        },
                    )
                    created["alert"].append(alert["_id"])
                    case = await setup._client.request(
                        "POST",
                        "/api/v1/case",
                        json={
                            "title": f"anysoar contract test case {n}",
                            "description": "Synthetic case created by anysoar's contract tests.",
                            "severity": severity,
                        },
                    )
                    created["case"].append(str(case["number"]))
                yield created
            finally:
                for kind, uids in created.items():
                    for uid in uids:
                        await setup._client.request("DELETE", f"/api/v1/{kind}/{uid}")

    @pytest_asyncio.fixture
    async def driver(self, lab: dict[str, list[str]]) -> AsyncIterator[TheHiveDriver]:
        async with TheHiveDriver() as driver:
            yield driver

    @pytest.fixture
    def case_uid(self, lab: dict[str, list[str]]) -> str:
        return lab["case"][0]

    async def test_analyzers_report(self, driver: TheHiveDriver) -> None:
        """The contract only checks the indicator comes back; here the analyzers must run."""
        indicator = Observable(type_id=ObservableTypeId.IP_ADDRESS, value="192.0.2.1")
        result = await driver.enrich_indicator(indicator)
        assert result.enrichments, "no analyzer ran; are Cortex analyzers enabled?"
        assert all(e.short_desc != "did not finish in time" for e in result.enrichments)
