import pytest

from anysoar.drivers.shuffle import ShuffleDriver
from anysoar.drivers.shuffle.incidents import to_case, verdict_label
from anysoar.errors import NotFoundError
from anysoar.interface import CaseQuery
from anysoar.models import IncidentFindingStatusId, Note, User, VerdictId

from .fake_shuffle import API_KEY, BASE_URL, FakeShuffle, new_incident, ui_incident


@pytest.fixture
def shuffle() -> FakeShuffle:
    return FakeShuffle()


@pytest.fixture
def soar(shuffle: FakeShuffle) -> ShuffleDriver:
    return ShuffleDriver(BASE_URL, API_KEY, transport=shuffle.transport())


class TestReadingWhatShuffleWrote:
    def test_ui_incident(self) -> None:
        case = to_case(ui_incident("i-1"))
        assert case.metadata.uid == "i-1"
        # Shuffle's 3 is "Resolved"; OCSF's 3 would be "On Hold".
        assert case.status_id is IncidentFindingStatusId.RESOLVED
        assert case.status == "Resolved"
        assert case.verdict_id is VerdictId.TRUE_POSITIVE  # parsed from the status entry
        assert case.message == 'Reported phishing: "Your mailbox is almost full"'
        assert case.desc == "Credential-harvesting link from it-support@example.net."
        assert [n.comment for n in case.notes] == ["Users reported it twice."]
        assert case.notes[0].owner == User(name="admin")
        assert case.notes[0].uid == "comment-1792113896731"
        assert case.assignee is None  # the UI stores an empty string
        assert [o.value for o in case.observables] == ["it-support@example.net", "203.0.113.25"]
        assert case.finding_info_list[0].uid == "i-1"

    def test_api_created_incident(self) -> None:
        case = to_case(new_incident("i-2"))
        assert case.status_id is IncidentFindingStatusId.NEW
        assert case.verdict_id is None
        assert case.assignee == User(name="analyst1@example.com", email_addr="analyst1@example.com")
        assert case.finding_info_list[0].title == 'Reported phishing: "Invoice INV-20431 overdue"'

    @pytest.mark.parametrize(
        ("shuffle_status", "ocsf"),
        [
            (1, IncidentFindingStatusId.NEW),
            (2, IncidentFindingStatusId.IN_PROGRESS),
            (3, IncidentFindingStatusId.RESOLVED),
            (4, IncidentFindingStatusId.CLOSED),
            (9, IncidentFindingStatusId.OTHER),
        ],
    )
    def test_status_mapping(self, shuffle_status: int, ocsf: IncidentFindingStatusId) -> None:
        record = new_incident("i") | {"status_id": shuffle_status}
        assert to_case(record).status_id is ocsf

    def test_incident_without_findings_describes_itself(self) -> None:
        record = new_incident("i-3")
        del record["finding_info"]
        record["title"] = "Bare incident"
        case = to_case(record)
        assert [(f.uid, f.title) for f in case.finding_info_list] == [("i-3", "Bare incident")]

    def test_verdict_labels(self) -> None:
        assert verdict_label(VerdictId.TRUE_POSITIVE) == "True Positive"
        assert verdict_label(VerdictId.INSUFFICIENT_DATA) == "Insufficient Data"


class TestWriting:
    async def test_add_note_as_shuffle_ui_comment(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        stored = await soar.add_note(
            shuffle.open_incident, Note(comment="Sender domain is a look-alike.", created_time=7)
        )
        assert (stored.uid, stored.created_time) == ("comment-7", 7)
        (entry,) = shuffle.record(shuffle.open_incident)["activity"]
        assert entry == {
            "id": "comment-7",
            "type": "comment",
            "user": "anysoar",
            "timestamp": 7,
            "content": "Sender domain is a look-alike.",
            "details": {},
            "attachments": [],
            "ai_handled": True,
        }
        case = await soar.get_case(shuffle.open_incident)
        assert case.notes[-1].comment == "Sender domain is a look-alike."

    async def test_note_keeps_its_author(self, soar: ShuffleDriver, shuffle: FakeShuffle) -> None:
        await soar.add_note(shuffle.open_incident, Note(comment="x", owner=User(name="triage-bot")))
        assert shuffle.record(shuffle.open_incident)["activity"][-1]["user"] == "triage-bot"

    async def test_close_case(self, soar: ShuffleDriver, shuffle: FakeShuffle) -> None:
        case = await soar.close_case(
            shuffle.open_incident, verdict_id=VerdictId.BENIGN, comment="Known supplier."
        )
        assert case.status_id is IncidentFindingStatusId.CLOSED
        assert case.verdict_id is VerdictId.BENIGN
        assert case.comment == "Known supplier."

        record = shuffle.record(shuffle.open_incident)
        assert (record["status_id"], record["status"]) == (4, "Closed")  # Shuffle's numbering
        assert (record["verdict_id"], record["verdict"]) == (5, "Benign")
        status, comment = record["activity"]
        assert (status["type"], status["content"]) == ("status", "Closed: Benign")
        assert (comment["type"], comment["content"]) == ("comment", "Known supplier.")

        fetched = await soar.get_case(shuffle.open_incident)
        assert fetched.status_id is IncidentFindingStatusId.CLOSED
        assert fetched.verdict_id is VerdictId.BENIGN

    async def test_writes_keep_fields_anysoar_does_not_know(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        await soar.add_note(shuffle.resolved_incident, Note(comment="x"))
        record = shuffle.record(shuffle.resolved_incident)
        assert record["metadata"] == {"extensions": {"custom_attributes": {"tlp": "TLP:AMBER"}}}
        assert record["_auto_repaired_fields"] == ["status"]
        assert len(record["activity"]) == 3


class TestNotFound:
    async def test_missing_incident(self, soar: ShuffleDriver) -> None:
        with pytest.raises(NotFoundError, match="case 'nope' not found"):
            await soar.get_case("nope")
        with pytest.raises(NotFoundError):
            await soar.add_note("nope", Note(comment="x"))

    async def test_other_datastore_entries_are_not_cases(self, soar: ShuffleDriver) -> None:
        # Shuffle returns any key regardless of the category asked for.
        with pytest.raises(NotFoundError):
            await soar.get_case("org-settings")

    async def test_org_is_looked_up_once(self, soar: ShuffleDriver, shuffle: FakeShuffle) -> None:
        await soar.get_case(shuffle.open_incident)
        await soar.get_case(shuffle.resolved_incident)
        lookups = [r for r in shuffle.requests if r.url.path == "/api/v1/users/getinfo"]
        assert len(lookups) == 1


class TestListing:
    async def test_lists_incidents_not_other_entries(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        page = await soar.list_cases()
        assert {c.metadata.uid for c in page.items} == {
            shuffle.open_incident,
            shuffle.resolved_incident,
        }

    async def test_status_filter_and_paging(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        new = await soar.list_cases(CaseQuery(status_ids=frozenset({IncidentFindingStatusId.NEW})))
        assert [c.metadata.uid for c in new.items] == [shuffle.open_incident]
        first = await soar.list_cases(CaseQuery(limit=1))
        assert first.next_cursor == "1"
        second = await soar.list_cases(CaseQuery(limit=1, cursor=first.next_cursor))
        assert second.next_cursor is None
        assert {first.items[0].metadata.uid, second.items[0].metadata.uid} == {
            shuffle.open_incident,
            shuffle.resolved_incident,
        }

    async def test_skips_unreadable_records(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        category = "shuffle-security_incidents"
        shuffle.datastore["not-json"] = {"key": "not-json", "category": category, "value": "{"}
        shuffle.datastore["no-id"] = {"key": "no-id", "category": category, "value": "{}"}
        uids = {c.metadata.uid for c in (await soar.list_cases()).items}
        assert uids == {shuffle.open_incident, shuffle.resolved_incident}

    async def test_odd_records_still_list_as_cases(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        # An entry in the incident category with an unknown status is still an incident.
        shuffle.put("shuffle-security_incidents", {"id": "odd", "status_id": "unknown"})
        odd = next(c for c in (await soar.list_cases()).items if c.metadata.uid == "odd")
        assert odd.status_id is IncidentFindingStatusId.OTHER
