import json

import httpx2
import pytest

from anysoar.drivers.thehive import TheHiveDriver
from anysoar.drivers.thehive.cases import case_status_filter, closing, to_case
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import CaseQuery
from anysoar.models import (
    IncidentFindingStatusId,
    Note,
    ObservableTypeId,
    SeverityId,
    User,
    VerdictId,
)

from .. import NO_WAIT
from .fake_thehive import API_KEY, BASE_URL, MINUTE, T0, FakeTheHive

Status = IncidentFindingStatusId
SERVICE_ACCOUNT = User(
    uid="anysoar@anysoar.lab", name="anysoar@anysoar.lab", email_addr="anysoar@anysoar.lab"
)


@pytest.fixture
def thehive() -> FakeTheHive:
    return FakeTheHive()


@pytest.fixture
def soar(thehive: FakeTheHive) -> TheHiveDriver:
    return TheHiveDriver(BASE_URL, API_KEY, retry=NO_WAIT, transport=thehive.transport())


class TestReadingCases:
    async def test_case(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        case = await soar.get_case(thehive.investigating)
        assert case.metadata.uid == thehive.investigating == "1"
        assert case.message == "Credential phishing: payroll@example.net"
        assert case.desc == "Synthetic case: Credential phishing: payroll@example.net."
        assert (case.status_id, case.status) == (Status.IN_PROGRESS, "InProgress")
        assert case.severity_id is SeverityId.MEDIUM
        assert case.time == T0 + 50 * MINUTE
        assert case.start_time == T0
        assert case.end_time is None
        assert case.verdict_id is None
        assert case.assignee == SERVICE_ACCOUNT
        assert case.unmapped is not None
        assert case.unmapped["_id"] == thehive.cases["1"]["_id"]

    async def test_findings_are_the_alerts_it_was_made_from(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        case = await soar.get_case(thehive.investigating)
        (info,) = case.finding_info_list
        assert (info.uid, info.title) == (
            thehive.imported,
            "Credential phishing: payroll@example.net",
        )
        assert [(o.type_id, o.value) for o in case.observables] == [
            (ObservableTypeId.EMAIL_ADDRESS, "payroll@example.net")
        ]

    async def test_case_without_alerts_is_its_own_finding(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        case = await soar.get_case(thehive.open_case)
        (info,) = case.finding_info_list
        assert (info.uid, info.title) == (thehive.open_case, "Suspicious login")
        assert info.types == ["phishing"]
        assert case.time == T0 + 40 * MINUTE  # never updated: its creation time

    async def test_comments_are_notes(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        (note,) = (await soar.get_case(thehive.investigating)).notes
        assert note.comment == "Started on this."
        assert note.owner == SERVICE_ACCOUNT
        assert note.created_time == T0 + 55 * MINUTE
        assert note.uid == thehive.comments["1"][0]["_id"]

    @pytest.mark.parametrize(
        ("status", "stage", "ocsf", "verdict"),
        [
            ("New", "New", Status.NEW, None),
            ("InProgress", "InProgress", Status.IN_PROGRESS, None),
            ("TruePositive", "Closed", Status.RESOLVED, VerdictId.TRUE_POSITIVE),
            ("FalsePositive", "Closed", Status.RESOLVED, VerdictId.FALSE_POSITIVE),
            ("Indeterminate", "Closed", Status.RESOLVED, VerdictId.INSUFFICIENT_DATA),
            ("Other", "Closed", Status.RESOLVED, VerdictId.OTHER),
            ("Duplicated", "Closed", Status.CLOSED, VerdictId.DUPLICATE),
            ("Contained", "Closed", Status.RESOLVED, None),  # a custom closing status
        ],
    )
    def test_status_mapping(
        self, status: str, stage: str, ocsf: Status, verdict: VerdictId | None
    ) -> None:
        case = to_case({"number": 1, "_createdAt": T0, "status": status, "stage": stage})
        assert (case.status_id, case.status, case.verdict_id) == (ocsf, status, verdict)

    def test_verdict_tag_names_what_the_status_cannot(self) -> None:
        record = {
            "number": 1,
            "_createdAt": T0,
            "status": "Other",
            "stage": "Closed",
            "tags": ["phishing", "verdict:benign"],
        }
        case = to_case(record)
        assert case.verdict_id is VerdictId.BENIGN
        assert case.finding_info_list[0].types == ["phishing"]

    def test_open_cases_have_no_verdict(self) -> None:
        record = {"number": 1, "_createdAt": T0, "stage": "InProgress", "tags": ["verdict:test"]}
        assert to_case(record).verdict_id is None

    async def test_not_found(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        with pytest.raises(NotFoundError):
            await soar.get_case("99")
        requests = len(thehive.requests)
        for uid in ("~8200", "case-1"):  # not a case number: TheHive is not asked
            with pytest.raises(NotFoundError):
                await soar.get_case(uid)
        assert len(thehive.requests) == requests


class TestListingCases:
    async def test_most_recently_updated_first(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        # Cases 2 and 5 were never updated, so TheHive alone would put them last.
        page = await soar.list_cases()
        assert [c.metadata.uid for c in page.items] == ["1", "3", "2", "5", "4"]
        assert page.next_cursor is None
        assert all(c.notes == [] for c in page.items)  # get_case fetches them

    @pytest.mark.parametrize("limit", [1, 2, 3])
    async def test_paging_matches_one_page(self, soar: TheHiveDriver, limit: int) -> None:
        uids: list[str | None] = []
        query = CaseQuery(limit=limit)
        while True:
            page = await soar.list_cases(query)
            assert len(page.items) <= limit
            uids += [c.metadata.uid for c in page.items]
            if page.next_cursor is None:
                break
            query = query.model_copy(update={"cursor": page.next_cursor})
        assert uids == ["1", "3", "2", "5", "4"]

    async def test_invalid_cursor(self, soar: TheHiveDriver) -> None:
        with pytest.raises(DriverError, match="cursor"):
            await soar.list_cases(CaseQuery(cursor="2"))

    @pytest.mark.parametrize(
        ("statuses", "expected"),
        [
            ({Status.NEW}, ["2", "5"]),
            ({Status.IN_PROGRESS}, ["1"]),
            ({Status.RESOLVED}, ["3"]),
            ({Status.CLOSED}, ["4"]),
            ({Status.NEW, Status.IN_PROGRESS}, ["1", "2", "5"]),
            ({Status.ON_HOLD}, []),
        ],
    )
    async def test_status_filter(
        self, soar: TheHiveDriver, statuses: set[Status], expected: list[str]
    ) -> None:
        page = await soar.list_cases(CaseQuery(status_ids=frozenset(statuses)))
        assert [c.metadata.uid for c in page.items] == expected

    def test_status_filter_for_one_status_is_not_wrapped(self) -> None:
        assert case_status_filter(frozenset({Status.CLOSED})) == {
            "_eq": {"_field": "status", "_value": "Duplicated"}
        }


class TestWritingCases:
    async def test_add_note(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        agent = User(name="anysoar agent")
        stored = await soar.add_note(thehive.open_case, Note(comment="Looks benign.", owner=agent))
        assert stored.comment == "Looks benign."
        assert stored.uid == thehive.comments["2"][0]["_id"]
        assert stored.created_time == thehive.now
        assert stored.owner == SERVICE_ACCOUNT  # TheHive writes as the API key's user
        notes = (await soar.get_case(thehive.open_case)).notes
        assert [n.comment for n in notes] == ["Looks benign."]

    async def test_add_note_to_missing_case(self, soar: TheHiveDriver) -> None:
        with pytest.raises(NotFoundError):
            await soar.add_note("99", Note(comment="x"))

    async def test_close(self, soar: TheHiveDriver, thehive: FakeTheHive) -> None:
        case = await soar.close_case(
            thehive.open_case, verdict_id=VerdictId.FALSE_POSITIVE, comment="Known scanner."
        )
        assert (case.status_id, case.status) == (Status.RESOLVED, "FalsePositive")
        assert case.verdict_id is VerdictId.FALSE_POSITIVE
        assert case.comment == "Known scanner."
        assert case.end_time == case.time == thehive.now
        patch = json.loads(thehive.requests[-5].content)  # before get_case's 4 requests
        assert patch == {
            "status": "FalsePositive",
            "tags": ["phishing"],
            "summary": "Known scanner.",
        }

    async def test_close_with_a_verdict_no_status_names(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        case = await soar.close_case(thehive.open_case, verdict_id=VerdictId.BENIGN)
        assert case.status == "Other"
        assert case.verdict_id is VerdictId.BENIGN
        assert thehive.cases["2"]["tags"] == ["phishing", "verdict:benign"]
        assert thehive.cases["2"]["summary"] is None  # no comment, summary left alone

    async def test_closing_again_replaces_the_verdict(
        self, soar: TheHiveDriver, thehive: FakeTheHive
    ) -> None:
        await soar.close_case(thehive.open_case, verdict_id=VerdictId.BENIGN)
        case = await soar.close_case(thehive.open_case, verdict_id=VerdictId.TRUE_POSITIVE)
        assert (case.status, case.verdict_id) == ("TruePositive", VerdictId.TRUE_POSITIVE)
        assert thehive.cases["2"]["tags"] == ["phishing"]

    @pytest.mark.parametrize(
        ("verdict", "status"),
        [
            (VerdictId.TRUE_POSITIVE, "TruePositive"),
            (VerdictId.DUPLICATE, "Duplicated"),
            (VerdictId.INSUFFICIENT_DATA, "Indeterminate"),
            (VerdictId.SUSPICIOUS, "Other"),
        ],
    )
    def test_closing_status(self, verdict: VerdictId, status: str) -> None:
        assert closing(verdict, ["x", "verdict:old"])[0] == status


class TestRetries:
    """What the shared retry rules mean for TheHive's requests."""

    @staticmethod
    def flaky(thehive: FakeTheHive, failures: int) -> tuple[TheHiveDriver, list[str]]:
        """A driver whose first ``failures`` requests get a 502 from a proxy in front."""
        sent: list[str] = []

        def handle(request: httpx2.Request) -> httpx2.Response:
            sent.append(f"{request.method} {request.url.path}")
            if len(sent) <= failures:
                return httpx2.Response(502, text="Bad Gateway")
            return thehive.handle(request)

        soar = TheHiveDriver(
            BASE_URL, API_KEY, retry=NO_WAIT, transport=httpx2.MockTransport(handle)
        )
        return soar, sent

    async def test_queries_are_retried(self, thehive: FakeTheHive) -> None:
        soar, sent = self.flaky(thehive, failures=2)
        page = await soar.list_cases()  # POST /api/v1/query, which only reads
        assert len(page.items) == 5
        assert sent[:3] == ["POST /api/v1/query"] * 3

    async def test_comments_are_not_repeated(self, thehive: FakeTheHive) -> None:
        sent: list[str] = []

        def fail_comments(request: httpx2.Request) -> httpx2.Response:
            sent.append(f"{request.method} {request.url.path}")
            if request.url.path.endswith("/comment"):
                return httpx2.Response(502, text="Bad Gateway")
            return thehive.handle(request)

        soar = TheHiveDriver(
            BASE_URL, API_KEY, retry=NO_WAIT, transport=httpx2.MockTransport(fail_comments)
        )
        with pytest.raises(DriverError) as error:
            await soar.add_note(thehive.open_case, Note(comment="once only"))
        assert error.value.retryable
        assert sent.count(f"POST /api/v1/case/{thehive.open_case}/comment") == 1
        assert thehive.comments[thehive.open_case] == []
