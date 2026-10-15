"""OCSF finding classes: Detection Finding (an alert) and Incident Finding (a case)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, JsonValue, computed_field, model_validator

from anysoar.models._base import OcsfModel, Timestamp
from anysoar.models.enums import (
    ActivityId,
    ConfidenceId,
    DetectionFindingStatusId,
    ImpactId,
    IncidentFindingStatusId,
    PriorityId,
    SeverityId,
    VerdictId,
)
from anysoar.models.objects import Enrichment, FindingInfo, Group, Metadata, Note, Observable, User

__all__ = ["DetectionFinding", "IncidentFinding"]


class _Finding(OcsfModel):
    """Attributes and behaviour shared by OCSF finding classes."""

    class_uid: int
    category_uid: Literal[2] = 2
    activity_id: ActivityId
    severity_id: SeverityId
    time: Timestamp
    metadata: Metadata

    status: str | None = None
    """Status caption, or the source's own status when ``status_id`` is Other."""
    confidence_id: ConfidenceId | None = None
    impact_id: ImpactId | None = None
    message: str | None = None
    comment: str | None = None
    start_time: Timestamp | None = None
    end_time: Timestamp | None = None
    observables: list[Observable] = Field(default_factory=list)
    enrichments: list[Enrichment] = Field(default_factory=list)
    notes: list[Note] = Field(default_factory=list)
    unmapped: dict[str, JsonValue] | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def type_uid(self) -> int:
        """OCSF event type: ``class_uid * 100 + activity_id``."""
        return self.class_uid * 100 + int(self.activity_id)

    @model_validator(mode="before")
    @classmethod
    def _check_type_uid(cls, data: Any) -> Any:
        """Accept ``type_uid`` on input only if it agrees with ``class_uid`` and ``activity_id``."""
        if not isinstance(data, dict) or "type_uid" not in data:
            return data
        data = dict(data)
        type_uid = data.pop("type_uid")
        class_uid = data.get("class_uid", cls.model_fields["class_uid"].default)
        activity_id = data.get("activity_id")
        try:
            expected = int(class_uid) * 100 + int(activity_id)
        except (TypeError, ValueError):
            return data  # field validation reports the underlying problem
        if type_uid != expected:
            raise ValueError(f"type_uid {type_uid} does not match class_uid and activity_id")
        return data


class DetectionFinding(_Finding):
    """OCSF Detection Finding (class 2004): an alert raised by a detection.

    Attributes ``assignee``, ``assignee_group``, ``priority_id``, ``verdict_id`` and ``src_url``
    belong to the OCSF ``incident`` profile; when any of them is set, ``incident`` is added to
    ``metadata.profiles`` on serialization.
    """

    class_uid: Literal[2004] = 2004
    finding_info: FindingInfo
    status_id: DetectionFindingStatusId | None = None
    is_alert: bool | None = None

    # OCSF "incident" profile
    assignee: User | None = None
    assignee_group: Group | None = None
    priority_id: PriorityId | None = None
    verdict_id: VerdictId | None = None
    src_url: str | None = None

    def ocsf_profiles(self) -> set[str]:
        incident = (self.assignee, self.assignee_group, self.priority_id, self.verdict_id)
        return {"incident"} if any(v is not None for v in (*incident, self.src_url)) else set()


class IncidentFinding(_Finding):
    """OCSF Incident Finding (class 2005): a case grouping one or more findings.

    Deviation from OCSF: the schema requires at least one of ``assignee`` or
    ``assignee_group``. anysoar does not enforce this, because unassigned cases are common in
    SOAR platforms and must still be representable.
    """

    class_uid: Literal[2005] = 2005
    status_id: IncidentFindingStatusId
    finding_info_list: list[FindingInfo] = Field(min_length=1)
    """The findings (e.g. alerts) this case groups."""
    desc: str | None = None
    assignee: User | None = None
    assignee_group: Group | None = None
    priority_id: PriorityId | None = None
    verdict_id: VerdictId | None = None
    is_suspected_breach: bool | None = None
    src_url: str | None = None
