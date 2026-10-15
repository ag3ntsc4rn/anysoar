import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from anysoar.models import (
    OCSF_VERSION,
    ActivityId,
    Alert,
    Case,
    DetectionFinding,
    DetectionFindingStatusId,
    FindingInfo,
    IncidentFinding,
    IncidentFindingStatusId,
    Metadata,
    Note,
    Observable,
    ObservableTypeId,
    Product,
    SeverityId,
    User,
    VerdictId,
    from_timestamp,
    to_timestamp,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ocsf"


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text())
    return data


def metadata() -> Metadata:
    return Metadata(product=Product(name="Example SOAR"))


def alert(**overrides: Any) -> DetectionFinding:
    fields: dict[str, Any] = {
        "activity_id": ActivityId.CREATE,
        "severity_id": SeverityId.HIGH,
        "time": 1_760_540_400_000,
        "metadata": metadata(),
        "finding_info": FindingInfo(uid="alert-1", title="Reported phishing"),
    }
    return DetectionFinding(**(fields | overrides))


class TestDetectionFinding:
    def test_minimal_alert_serializes_to_ocsf(self) -> None:
        assert alert().to_ocsf() == {
            "class_uid": 2004,
            "category_uid": 2,
            "activity_id": 1,
            "type_uid": 200401,
            "severity_id": 4,
            "time": 1_760_540_400_000,
            "metadata": {"version": OCSF_VERSION, "product": {"name": "Example SOAR"}},
            "finding_info": {"uid": "alert-1", "title": "Reported phishing"},
        }

    def test_aliases(self) -> None:
        assert Alert is DetectionFinding
        assert Case is IncidentFinding

    def test_fixture_round_trips_including_unmodelled_attributes(self) -> None:
        raw = load("phishing_alert.json")
        parsed = DetectionFinding.from_ocsf(raw)

        assert parsed.status_id is DetectionFindingStatusId.NEW
        assert parsed.observables[2].type_id is ObservableTypeId.IP_ADDRESS
        assert parsed.notes[0].comment == "Reported via the phishing button."
        assert parsed.to_ocsf() == raw

    def test_type_uid_must_match_class_and_activity(self) -> None:
        raw = load("phishing_alert.json") | {"type_uid": 200402}
        with pytest.raises(ValidationError, match="type_uid"):
            DetectionFinding.from_ocsf(raw)

    def test_type_uid_follows_activity(self) -> None:
        finding = alert()
        finding.activity_id = ActivityId.CLOSE
        assert finding.to_ocsf()["type_uid"] == 200403

    def test_wrong_class_uid_rejected(self) -> None:
        raw = load("phishing_alert.json") | {"class_uid": 2005, "type_uid": 200501}
        with pytest.raises(ValidationError, match="class_uid"):
            DetectionFinding.from_ocsf(raw)

    def test_unknown_enum_value_rejected(self) -> None:
        with pytest.raises(ValidationError, match="severity_id"):
            alert(severity_id=42)

    def test_alert_and_case_status_enums_differ(self) -> None:
        # 3 is "Suppressed" for alerts but "On Hold" for cases in OCSF.
        assert DetectionFindingStatusId(3).name == "SUPPRESSED"
        assert IncidentFindingStatusId(3).name == "ON_HOLD"

    def test_incident_profile_declared_when_its_attributes_are_used(self) -> None:
        assert "profiles" not in alert().to_ocsf()["metadata"]
        triaged = alert(verdict_id=VerdictId.TRUE_POSITIVE, assignee=User(name="analyst"))
        assert triaged.to_ocsf()["metadata"]["profiles"] == ["incident"]

    def test_empty_arrays_and_none_omitted(self) -> None:
        out = alert(observables=[], message=None).to_ocsf()
        assert "observables" not in out
        assert "message" not in out

    def test_invalid_assignment_rejected(self) -> None:
        finding = alert()
        with pytest.raises(ValidationError):
            finding.severity_id = 1000  # type: ignore[assignment]


class TestIncidentFinding:
    def case(self, **overrides: Any) -> IncidentFinding:
        fields: dict[str, Any] = {
            "activity_id": ActivityId.CREATE,
            "severity_id": SeverityId.MEDIUM,
            "status_id": IncidentFindingStatusId.NEW,
            "time": 1_760_540_400_000,
            "metadata": metadata(),
            "finding_info_list": [FindingInfo(uid="alert-1")],
        }
        return IncidentFinding(**(fields | overrides))

    def test_minimal_case_serializes_to_ocsf(self) -> None:
        out = self.case().to_ocsf()
        assert out["class_uid"] == 2005
        assert out["type_uid"] == 200501
        assert out["status_id"] == 1
        assert out["finding_info_list"] == [{"uid": "alert-1"}]

    def test_case_needs_at_least_one_finding(self) -> None:
        with pytest.raises(ValidationError, match="finding_info_list"):
            self.case(finding_info_list=[])

    def test_unassigned_case_is_allowed(self) -> None:
        # Deliberate deviation from OCSF's at_least_one(assignee, assignee_group).
        assert self.case().assignee is None

    def test_notes(self) -> None:
        note = Note(comment="Confirmed phishing; blocking sender.", owner=User(uid="u-1"))
        out = self.case(notes=[note]).to_ocsf()
        assert out["notes"] == [{"comment": note.comment, "owner": {"uid": "u-1"}}]


class TestObjects:
    @pytest.mark.parametrize("model", [Product, User])
    def test_at_least_one_identifier_required(self, model: type[Product | User]) -> None:
        with pytest.raises(ValidationError, match="at least one of"):
            model()

    def test_user_account_satisfies_constraint(self) -> None:
        assert User.model_validate({"account": {"name": "svc"}}).model_extra == {
            "account": {"name": "svc"}
        }

    def test_observable(self) -> None:
        obs = Observable(type_id=ObservableTypeId.URL_STRING, value="https://example.net")
        assert obs.to_ocsf() == {"type_id": 6, "value": "https://example.net"}


class TestTimestamps:
    def test_round_trip(self) -> None:
        dt = datetime(2025, 10, 15, 15, 0, tzinfo=UTC)
        assert to_timestamp(dt) == 1_760_540_400_000
        assert from_timestamp(1_760_540_400_000) == dt

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            to_timestamp(datetime(2026, 10, 15))
