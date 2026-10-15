import ipaddress
from collections.abc import Iterator

import pytest

from anysoar.drivers.mock import MockDriver
from anysoar.drivers.mock.seed import BASE_TIME
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import ActionTier, AlertQuery, Capability, PlaybookRunStatus
from anysoar.models import (
    ActivityId,
    DetectionFinding,
    DetectionFindingStatusId,
    IncidentFinding,
    IncidentFindingStatusId,
    Note,
    Observable,
    ObservableTypeId,
    ReputationScoreId,
    SeverityId,
    VerdictId,
)

NOW = BASE_TIME + 6 * 60 * 60 * 1000
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
DOC_NETWORKS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


@pytest.fixture
def soar() -> MockDriver:
    return MockDriver(clock=lambda: NOW)


async def all_alerts(soar: MockDriver) -> list[DetectionFinding]:
    return (await soar.list_alerts(AlertQuery(limit=500))).items


def all_observables(findings: list[DetectionFinding]) -> Iterator[Observable]:
    for finding in findings:
        yield from finding.observables


class TestSeed:
    async def test_describe(self, soar: MockDriver) -> None:
        info = await soar.describe()
        assert info.name == "mock"
        assert info.capabilities == frozenset(Capability)
        assert info.soar_product == "Mock SOAR"

    async def test_scenario_size(self, soar: MockDriver) -> None:
        alerts = await all_alerts(soar)
        assert len(alerts) == 8
        assert all("Phishing" in a.finding_info.types for a in alerts)
        for uid in ("case-0001", "case-0002", "case-0003"):
            assert (await soar.get_case(uid)).metadata.uid == uid

    async def test_cases_reference_existing_alerts(self, soar: MockDriver) -> None:
        alert_uids = {a.finding_info.uid for a in await all_alerts(soar)}
        for uid in ("case-0001", "case-0002", "case-0003"):
            case = await soar.get_case(uid)
            assert {i.uid for i in case.finding_info_list} <= alert_uids

    async def test_only_synthetic_indicators(self, soar: MockDriver) -> None:
        for o in all_observables(await all_alerts(soar)):
            assert o.value is not None
            if o.type_id is ObservableTypeId.IP_ADDRESS:
                ip = ipaddress.ip_address(o.value)
                assert any(ip in net for net in DOC_NETWORKS), o.value
            elif o.type_id in (ObservableTypeId.EMAIL_ADDRESS, ObservableTypeId.URL_STRING):
                host = o.value.split("@")[-1] if "@" in o.value else o.value.split("/")[2]
                is_doc_ip = host.replace(".", "").isdigit() and any(
                    ipaddress.ip_address(host) in net for net in DOC_NETWORKS
                )
                assert is_doc_ip or host.endswith(RESERVED_DOMAINS), o.value

    async def test_seeded_data_round_trips_as_ocsf(self, soar: MockDriver) -> None:
        for alert in await all_alerts(soar):
            assert DetectionFinding.from_ocsf(alert.to_ocsf()) == alert
        case = await soar.get_case("case-0001")
        assert IncidentFinding.from_ocsf(case.to_ocsf()) == case

    async def test_instances_are_isolated(self, soar: MockDriver) -> None:
        await soar.close_case("case-0001", verdict_id=VerdictId.TRUE_POSITIVE)
        other = MockDriver()
        assert (await other.get_case("case-0001")).status_id is IncidentFindingStatusId.IN_PROGRESS

    async def test_returned_objects_are_copies(self, soar: MockDriver) -> None:
        alert = await soar.get_alert("alert-0001")
        alert.observables.clear()
        assert (await soar.get_alert("alert-0001")).observables


class TestAlerts:
    async def test_newest_first(self, soar: MockDriver) -> None:
        alerts = await all_alerts(soar)
        times = [a.finding_info.created_time or a.time for a in alerts]
        assert times == sorted(times, reverse=True)
        assert alerts[0].finding_info.uid == "alert-0008"

    async def test_filters(self, soar: MockDriver) -> None:
        new = await soar.list_alerts(
            AlertQuery(status_ids=frozenset({DetectionFindingStatusId.NEW}))
        )
        assert {a.finding_info.uid for a in new.items} == {
            "alert-0003",
            "alert-0004",
            "alert-0005",
            "alert-0008",
        }
        high = await soar.list_alerts(AlertQuery(min_severity_id=SeverityId.HIGH))
        assert {a.finding_info.uid for a in high.items} == {
            "alert-0001",
            "alert-0002",
            "alert-0008",
        }
        window = await soar.list_alerts(AlertQuery(since=BASE_TIME, until=BASE_TIME + 60_000))
        assert [a.finding_info.uid for a in window.items] == ["alert-0001"]

    async def test_pagination(self, soar: MockDriver) -> None:
        first = await soar.list_alerts(AlertQuery(limit=5))
        assert len(first.items) == 5
        assert first.next_cursor is not None
        second = await soar.list_alerts(AlertQuery(limit=5, cursor=first.next_cursor))
        assert len(second.items) == 3
        assert second.next_cursor is None

    async def test_invalid_cursor(self, soar: MockDriver) -> None:
        with pytest.raises(DriverError):
            await soar.list_alerts(AlertQuery(cursor="not-a-cursor"))

    async def test_unknown_alert(self, soar: MockDriver) -> None:
        with pytest.raises(NotFoundError):
            await soar.get_alert("alert-9999")


class TestCases:
    async def test_add_note_assigns_uid_and_time(self, soar: MockDriver) -> None:
        stored = await soar.add_note("case-0002", Note(comment="Looking at the attachment."))
        assert stored.uid == "note-0001"
        assert stored.created_time == NOW
        case = await soar.get_case("case-0002")
        assert case.notes[-1] == stored
        assert case.activity_id is ActivityId.UPDATE

    async def test_add_note_keeps_caller_uid(self, soar: MockDriver) -> None:
        stored = await soar.add_note("case-0002", Note(comment="x", uid="mine", created_time=1))
        assert (stored.uid, stored.created_time) == ("mine", 1)

    async def test_close_case_resolves_its_alerts(self, soar: MockDriver) -> None:
        case = await soar.close_case(
            "case-0001", verdict_id=VerdictId.TRUE_POSITIVE, comment="Sender blocked."
        )
        assert case.status_id is IncidentFindingStatusId.CLOSED
        assert case.verdict_id is VerdictId.TRUE_POSITIVE
        assert case.activity_id is ActivityId.CLOSE
        assert (case.comment, case.end_time) == ("Sender blocked.", NOW)
        for uid in ("alert-0001", "alert-0002"):
            alert = await soar.get_alert(uid)
            assert alert.status_id is DetectionFindingStatusId.RESOLVED
            assert alert.verdict_id is VerdictId.TRUE_POSITIVE

    async def test_closing_keeps_alert_creation_order(self, soar: MockDriver) -> None:
        before = [a.finding_info.uid for a in await all_alerts(soar)]
        await soar.close_case("case-0001", verdict_id=VerdictId.TRUE_POSITIVE)
        assert [a.finding_info.uid for a in await all_alerts(soar)] == before

    @pytest.mark.parametrize("operation", ["get_case", "add_note", "close_case"])
    async def test_unknown_case(self, soar: MockDriver, operation: str) -> None:
        with pytest.raises(NotFoundError):
            if operation == "get_case":
                await soar.get_case("case-9999")
            elif operation == "add_note":
                await soar.add_note("case-9999", Note(comment="x"))
            else:
                await soar.close_case("case-9999", verdict_id=VerdictId.BENIGN)


class TestEnrichment:
    async def test_known_indicator(self, soar: MockDriver) -> None:
        ip = Observable(type_id=ObservableTypeId.IP_ADDRESS, value="203.0.113.25")
        result = await soar.enrich_indicator(ip)
        assert result.observable.reputation is not None
        assert result.observable.reputation.score_id is ReputationScoreId.PROBABLY_MALICIOUS
        assert result.observable.reputation.base_score == 90.0
        (enrichment,) = result.enrichments
        assert enrichment.data == {
            "verdict": "probably_malicious",
            "tags": ["phishing-infrastructure"],
            "related_alerts": ["alert-0001", "alert-0002"],
            "related_cases": ["case-0001"],
        }

    async def test_internal_indicator_is_safe(self, soar: MockDriver) -> None:
        sender = Observable(type_id=ObservableTypeId.EMAIL_ADDRESS, value="news@example.com")
        result = await soar.enrich_indicator(sender)
        assert result.observable.reputation is not None
        assert result.observable.reputation.score_id is ReputationScoreId.SAFE

    async def test_unknown_indicator(self, soar: MockDriver) -> None:
        ip = Observable(type_id=ObservableTypeId.IP_ADDRESS, value="192.0.2.200")
        result = await soar.enrich_indicator(ip)
        assert result.observable.reputation is not None
        assert result.observable.reputation.score_id is ReputationScoreId.UNKNOWN
        assert result.enrichments[0].data == {
            "verdict": "unknown",
            "tags": [],
            "related_alerts": [],
            "related_cases": [],
        }

    async def test_type_must_match(self, soar: MockDriver) -> None:
        wrong_type = Observable(type_id=ObservableTypeId.HOSTNAME, value="203.0.113.25")
        result = await soar.enrich_indicator(wrong_type)
        assert result.observable.reputation is not None
        assert result.observable.reputation.score_id is ReputationScoreId.UNKNOWN

    async def test_deterministic(self, soar: MockDriver) -> None:
        url = Observable(type_id=ObservableTypeId.URL_STRING, value="http://198.51.100.23/reset")
        first = await soar.enrich_indicator(url)
        assert await soar.enrich_indicator(url) == first
        assert await MockDriver().enrich_indicator(url) == first


class TestPlaybooks:
    async def test_catalogue(self, soar: MockDriver) -> None:
        playbooks = {p.uid: p for p in await soar.list_playbooks()}
        assert "pb-block-sender" in playbooks
        assert playbooks["pb-disable-account"].tier is ActionTier.DESTRUCTIVE

    async def test_run_progresses_one_step_per_poll(self, soar: MockDriver) -> None:
        run = await soar.run_playbook(
            "pb-block-sender", case_uid="case-0001", inputs={"sender": "it-support@example.net"}
        )
        assert (run.uid, run.status) == ("run-0001", PlaybookRunStatus.QUEUED)
        running = await soar.get_playbook_run(run.uid)
        assert running.status is PlaybookRunStatus.RUNNING
        assert running.started_time == NOW
        done = await soar.get_playbook_run(run.uid)
        assert done.status is PlaybookRunStatus.SUCCEEDED
        assert done.ended_time == NOW
        assert done.outputs == {"inputs": {"sender": "it-support@example.net"}}
        assert await soar.get_playbook_run(run.uid) == done

    async def test_finished_run_notes_the_case(self, soar: MockDriver) -> None:
        run = await soar.run_playbook("pb-notify-reporter", case_uid="case-0001")
        for _ in range(2):
            await soar.get_playbook_run(run.uid)
        note = (await soar.get_case("case-0001")).notes[-1]
        assert note.title == "Playbook run"
        assert run.uid in note.comment
        assert "succeeded" in note.comment

    async def test_missing_inputs_fail_the_run(self, soar: MockDriver) -> None:
        run = await soar.run_playbook("pb-block-url", alert_uid="alert-0008")
        await soar.get_playbook_run(run.uid)
        failed = await soar.get_playbook_run(run.uid)
        assert failed.status is PlaybookRunStatus.FAILED
        assert failed.message == "missing required inputs: url"

    async def test_unknown_references(self, soar: MockDriver) -> None:
        with pytest.raises(NotFoundError):
            await soar.run_playbook("pb-nope")
        with pytest.raises(NotFoundError):
            await soar.run_playbook("pb-notify-reporter", case_uid="case-9999")
        with pytest.raises(NotFoundError):
            await soar.run_playbook("pb-notify-reporter", alert_uid="alert-9999")
        with pytest.raises(NotFoundError):
            await soar.get_playbook_run("run-9999")


async def test_context_manager() -> None:
    async with MockDriver() as soar:
        assert (await soar.get_alert("alert-0001")).finding_info.uid == "alert-0001"
