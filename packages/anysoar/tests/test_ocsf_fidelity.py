"""Check anysoar's models against a snapshot of the OCSF schema.

The snapshot is refreshed with ``scripts/update_ocsf_snapshot.py``. These tests guarantee that
anysoar never invents attribute names or enum values, and never makes an OCSF-required
attribute optional.
"""

import json
from enum import IntEnum
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from anysoar import models
from anysoar.models import enums

SNAPSHOT: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "ocsf" / "schema_snapshot.json").read_text()
)

# (model, snapshot group, OCSF name, OCSF profiles the model may use)
MODELS: list[tuple[type[BaseModel], str, str, tuple[str, ...]]] = [
    (models.DetectionFinding, "classes", "detection_finding", ("incident",)),
    (models.IncidentFinding, "classes", "incident_finding", ()),
    (models.Enrichment, "objects", "enrichment", ()),
    (models.FindingInfo, "objects", "finding_info", ()),
    (models.Group, "objects", "group", ()),
    (models.Metadata, "objects", "metadata", ()),
    (models.Note, "objects", "note", ()),
    (models.Observable, "objects", "observable", ()),
    (models.Product, "objects", "product", ()),
    (models.Reputation, "objects", "reputation", ()),
    (models.User, "objects", "user", ()),
]

# (enum, snapshot group, OCSF name, attribute)
ENUMS: list[tuple[type[IntEnum], str, str, str]] = [
    (enums.ActivityId, "classes", "detection_finding", "activity_id"),
    (enums.ActivityId, "classes", "incident_finding", "activity_id"),
    (enums.SeverityId, "classes", "detection_finding", "severity_id"),
    (enums.SeverityId, "classes", "incident_finding", "severity_id"),
    (enums.ConfidenceId, "classes", "detection_finding", "confidence_id"),
    (enums.ConfidenceId, "classes", "incident_finding", "confidence_id"),
    (enums.ImpactId, "classes", "detection_finding", "impact_id"),
    (enums.ImpactId, "classes", "incident_finding", "impact_id"),
    (enums.PriorityId, "classes", "incident_finding", "priority_id"),
    (enums.PriorityId, "profiles", "incident", "priority_id"),
    (enums.VerdictId, "classes", "incident_finding", "verdict_id"),
    (enums.VerdictId, "profiles", "incident", "verdict_id"),
    (enums.DetectionFindingStatusId, "classes", "detection_finding", "status_id"),
    (enums.IncidentFindingStatusId, "classes", "incident_finding", "status_id"),
    (enums.ObservableTypeId, "objects", "observable", "type_id"),
    (enums.ReputationScoreId, "objects", "reputation", "score_id"),
    (enums.UserTypeId, "objects", "user", "type_id"),
]

# Required by OCSF but given a fixed value or derived by anysoar, so not required on input.
NOT_REQUIRED_ON_INPUT = {"class_uid", "category_uid", "type_uid", "version"}


def ocsf(group: str, name: str) -> dict[str, Any]:
    definition: dict[str, Any] = SNAPSHOT[group][name]
    return definition


def declared(model: type[BaseModel]) -> set[str]:
    return set(model.model_fields) | set(model.model_computed_fields)


def test_snapshot_version_matches_models() -> None:
    assert SNAPSHOT["version"] == models.OCSF_VERSION


@pytest.mark.parametrize(("model", "group", "name", "profiles"), MODELS)
def test_no_invented_attributes(
    model: type[BaseModel], group: str, name: str, profiles: tuple[str, ...]
) -> None:
    allowed = set(ocsf(group, name)["attributes"])
    for profile in profiles:
        allowed |= set(ocsf("profiles", profile)["attributes"])
    assert declared(model) - allowed == set()


@pytest.mark.parametrize(("model", "group", "name", "profiles"), MODELS)
def test_ocsf_required_attributes_are_modelled_and_required(
    model: type[BaseModel], group: str, name: str, profiles: tuple[str, ...]
) -> None:
    required = set(ocsf(group, name)["required"])
    assert required - declared(model) == set()
    for attr in required - NOT_REQUIRED_ON_INPUT:
        assert model.model_fields[attr].is_required(), f"{attr} must be required"


def member_name(caption: str) -> str:
    """OCSF caption to enum member name, e.g. "Suspicious/Risky" -> SUSPICIOUS_RISKY."""
    return "_".join("".join(c if c.isalnum() else " " for c in caption.upper()).split())


@pytest.mark.parametrize(("enum", "group", "name", "attr"), ENUMS)
def test_enum_matches_ocsf(enum: type[IntEnum], group: str, name: str, attr: str) -> None:
    captions: dict[str, str] = ocsf(group, name)["enums"][attr]
    expected = {int(value): member_name(caption) for value, caption in captions.items()}
    assert {m.value: m.name for m in enum} == expected
