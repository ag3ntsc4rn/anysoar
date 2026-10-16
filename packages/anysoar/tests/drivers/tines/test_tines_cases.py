import json

import pytest

from anysoar.drivers.tines import TinesDriver
from anysoar.drivers.tines.cases import to_case, verdict_tag
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import CaseQuery
from anysoar.models import IncidentFindingStatusId, Note, SeverityId, User, VerdictId

from .fake_tines import API_KEY, BASE_URL, FakeTines, tines_case


@pytest.fixture
def tines() -> FakeTines:
    return FakeTines()


@pytest.fixture
def soar(tines: FakeTines) -> TinesDriver:
    return TinesDriver(BASE_URL, API_KEY, transport=tines.transport())


class TestReadingTinesCases:
    def test_open_case(self) -> None:
        case = to_case(tines_case(42, "Reported phishing", updated=30))
        assert case.metadata.uid == "42"
        assert case.status_id is IncidentFindingStatusId.NEW
        assert case.status == "To do"
        assert case.severity_id is SeverityId.HIGH
        assert case.message == "Reported phishing"
        assert case.desc == "Synthetic case 42 reported by a user."
        assert case.time == 1790847000000  # updated_at, 2026-10-01T09:30:00Z
        assert case.verdict_id is None
        assert case.end_time is None
        assert case.assignee == User(
            uid="170", name="Robin Analyst", email_addr="robin@example.com"
        )
        (info,) = case.finding_info_list
        assert (info.uid, info.title) == ("42", "Reported phishing")
        assert info.src_url == f"{BASE_URL}/team/276/cases/42"

    def test_closed_case_with_verdict_tag(self) -> None:
        record = tines_case(
            41, "x", status="CLOSED", sub_status="Resolved", tags=["phishing", "verdict:benign"]
        )
        case = to_case(record)
        assert case.status_id is IncidentFindingStatusId.RESOLVED
        assert case.verdict_id is VerdictId.BENIGN
        assert case.end_time == case.time
        assert case.finding_info_list[0].types == ["phishing"]  # the verdict tag is not a type

    @pytest.mark.parametrize(
        ("status", "sub_status", "ocsf"),
        [
            ("OPEN", "To do", IncidentFindingStatusId.NEW),
            ("OPEN", "Triage", IncidentFindingStatusId.NEW),
            ("OPEN", "In progress", IncidentFindingStatusId.IN_PROGRESS),
            ("OPEN", "Investigating", IncidentFindingStatusId.IN_PROGRESS),
            ("OPEN", "On hold", IncidentFindingStatusId.ON_HOLD),
            ("OPEN", "Waiting on customer", IncidentFindingStatusId.ON_HOLD),
            ("CLOSED", "Resolved", IncidentFindingStatusId.RESOLVED),
            ("CLOSED", "Duplicate", IncidentFindingStatusId.CLOSED),
            ("ARCHIVED", "x", IncidentFindingStatusId.OTHER),
        ],
    )
    def test_status_mapping(
        self, status: str, sub_status: str, ocsf: IncidentFindingStatusId
    ) -> None:
        assert to_case(tines_case(1, "x", status=status, sub_status=sub_status)).status_id is ocsf

    @pytest.mark.parametrize(
        ("priority", "severity"),
        [
            ("CRITICAL", SeverityId.CRITICAL),
            ("INFO", SeverityId.INFORMATIONAL),
            ("", SeverityId.UNKNOWN),
        ],
    )
    def test_priority_mapping(self, priority: str, severity: SeverityId) -> None:
        assert to_case(tines_case(1, "x", priority=priority)).severity_id is severity

    def test_comments_are_notes(self, tines: FakeTines) -> None:
        case = to_case(tines._case(43))
        (note,) = case.notes
        assert note.comment == "Users reported it twice."
        assert note.owner is not None and note.owner.email_addr == "robin@example.com"
        assert note.created_time is not None

    def test_verdict_tags(self) -> None:
        assert verdict_tag(VerdictId.FALSE_POSITIVE) == "verdict:false_positive"


class TestListing:
    async def test_most_recently_updated_first(self, soar: TinesDriver) -> None:
        page = await soar.list_cases()
        assert [c.metadata.uid for c in page.items] == ["42", "43", "41"]
        assert page.next_cursor is None

    async def test_pages(self, soar: TinesDriver, tines: FakeTines) -> None:
        first = await soar.list_cases(CaseQuery(limit=2))
        assert [c.metadata.uid for c in first.items] == ["42", "43"]
        assert first.next_cursor == "2"
        second = await soar.list_cases(CaseQuery(limit=2, cursor=first.next_cursor))
        assert [c.metadata.uid for c in second.items] == ["41"]
        assert second.next_cursor is None
        assert tines.requests[-1].url.params["page"] == "2"
        assert tines.requests[-1].url.params["order"] == "RECENTLY_EDITED"

    async def test_status_filter(self, soar: TinesDriver) -> None:
        query = CaseQuery(status_ids=frozenset({IncidentFindingStatusId.IN_PROGRESS}))
        assert [c.metadata.uid for c in (await soar.list_cases(query)).items] == ["43"]

    async def test_team(self, tines: FakeTines) -> None:
        soar = TinesDriver(BASE_URL, API_KEY, team_id=276, transport=tines.transport())
        await soar.list_cases()
        assert tines.requests[-1].url.params["team_id"] == "276"

    async def test_bad_cursor(self, soar: TinesDriver) -> None:
        with pytest.raises(DriverError, match="invalid cursor"):
            await soar.list_cases(CaseQuery(cursor="abc"))


class TestWriting:
    async def test_add_note(self, soar: TinesDriver, tines: FakeTines) -> None:
        stored = await soar.add_note("42", Note(comment="Sender domain is a look-alike."))
        (comment,) = tines.comments[42]
        assert comment["value"] == "Sender domain is a look-alike."
        assert stored.uid == str(comment["id"])
        assert stored.created_time is not None
        assert stored.owner is not None and stored.owner.email_addr == "anysoar-bot@example.com"
        assert "author_email" not in json.loads(tines.requests[-1].content)

    async def test_add_note_for_a_person(self, soar: TinesDriver, tines: FakeTines) -> None:
        owner = User(name="Robin", email_addr="robin@example.com")
        stored = await soar.add_note("42", Note(comment="Checked it.", owner=owner))
        assert json.loads(tines.requests[-1].content)["author_email"] == "robin@example.com"
        assert stored.owner is not None and stored.owner.name == "Robin Analyst"

    async def test_get_case_reads_every_comment(self, soar: TinesDriver, tines: FakeTines) -> None:
        for i in range(25):  # more than the 20 activities Tines embeds in a case
            tines.comment(42, f"comment {i}", tines.cases[42]["author"])
        case = await soar.get_case("42")
        assert len(case.notes) == 25

    async def test_close_case(self, soar: TinesDriver, tines: FakeTines) -> None:
        tines.cases[42]["tags"] = [{"id": 1, "name": "verdict:unknown"}, {"id": 2, "name": "vip"}]
        case = await soar.close_case(
            "42", verdict_id=VerdictId.FALSE_POSITIVE, comment="Known marketing sender."
        )
        assert case.status_id is IncidentFindingStatusId.RESOLVED
        assert case.verdict_id is VerdictId.FALSE_POSITIVE
        assert [t["name"] for t in tines.cases[42]["tags"]] == ["vip", "verdict:false_positive"]
        update = next(json.loads(r.content) for r in tines.requests if r.method == "PUT")
        assert update == {
            "status": "closed",
            "add_tag_names": ["verdict:false_positive"],
            "remove_tag_names": ["verdict:unknown"],
        }
        assert case.notes[-1].comment == "Closed as False Positive.\n\nKnown marketing sender."

    async def test_close_without_comment(self, soar: TinesDriver, tines: FakeTines) -> None:
        await soar.close_case("42", verdict_id=VerdictId.BENIGN)
        assert tines.comments[42][-1]["value"] == "Closed as Benign."


class TestMissingCases:
    @pytest.mark.parametrize("uid", ["999", "not-a-number"])
    async def test_not_found(self, soar: TinesDriver, uid: str) -> None:
        with pytest.raises(NotFoundError, match=f"case '{uid}' not found"):
            await soar.get_case(uid)
        with pytest.raises(NotFoundError):
            await soar.add_note(uid, Note(comment="x"))
        with pytest.raises(NotFoundError):
            await soar.close_case(uid, verdict_id=VerdictId.BENIGN)
