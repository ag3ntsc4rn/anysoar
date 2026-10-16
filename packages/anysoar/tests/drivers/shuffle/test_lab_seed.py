"""demo/shuffle/seed.py writes records the Shuffle driver reads back as the mock's cases."""

import importlib.util
from pathlib import Path
from types import ModuleType

from anysoar.drivers.mock import seed
from anysoar.drivers.shuffle.incidents import to_case
from anysoar.models import IncidentFindingStatusId

SEED = Path(__file__).parents[5] / "demo" / "shuffle" / "seed.py"


def load_seed_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lab_seed", SEED)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seeded_incidents_read_back_as_the_mock_cases() -> None:
    lab = load_seed_script()
    for mock_case in seed.build_cases(seed.build_alerts()):
        assert mock_case.metadata.uid is not None
        record = lab.to_record(mock_case)
        assert record["id"] == lab.incident_id(mock_case.metadata.uid)
        case = to_case(record)
        assert case.metadata.uid == record["id"]
        assert case.status_id is mock_case.status_id
        assert case.verdict_id == mock_case.verdict_id
        assert case.message == mock_case.message
        assert case.severity_id is mock_case.severity_id
        assert [n.comment for n in case.notes] == [n.comment for n in mock_case.notes] + (
            [mock_case.comment] if mock_case.comment else []
        )
        assert {(o.type_id, o.value) for o in case.observables} == {
            (o.type_id, o.value) for o in mock_case.observables
        }
        assert [f.uid for f in case.finding_info_list] == [
            f.uid for f in mock_case.finding_info_list
        ]


def test_ids_are_stable_and_closed_case_uses_shuffle_numbering() -> None:
    lab = load_seed_script()
    assert lab.incident_id("case-0001") == lab.incident_id("case-0001")
    closed = next(
        c
        for c in seed.build_cases(seed.build_alerts())
        if c.status_id is IncidentFindingStatusId.CLOSED
    )
    record = lab.to_record(closed)
    assert (record["status_id"], record["status"]) == (4, "Closed")
    assert record["activity"][-2]["content"] == "Closed: True Positive"


def test_seeded_notes_are_not_marked_as_ai() -> None:
    lab = load_seed_script()
    for case in seed.build_cases(seed.build_alerts()):
        record = lab.to_record(case)
        comments = [a for a in record["activity"] if a["type"] == "comment"]
        assert all(a["ai_handled"] is False for a in comments)
        assert all(a["user"] != "anysoar" for a in record["activity"])
