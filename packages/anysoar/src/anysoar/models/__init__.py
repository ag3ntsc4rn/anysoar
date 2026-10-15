"""OCSF-aligned data models.

anysoar uses OCSF classes rather than its own schema:

- an **alert** is an OCSF Detection Finding (:class:`DetectionFinding`, aliased :data:`Alert`)
- a **case** is an OCSF Incident Finding (:class:`IncidentFinding`, aliased :data:`Case`)
- an **indicator** is an OCSF observable (:class:`Observable`)
"""

from anysoar.models._base import (
    OCSF_VERSION,
    OcsfModel,
    Timestamp,
    from_timestamp,
    now_timestamp,
    to_timestamp,
)
from anysoar.models.enums import (
    ActivityId,
    ConfidenceId,
    DetectionFindingStatusId,
    ImpactId,
    IncidentFindingStatusId,
    ObservableTypeId,
    PriorityId,
    ReputationScoreId,
    SeverityId,
    UserTypeId,
    VerdictId,
)
from anysoar.models.findings import DetectionFinding, IncidentFinding
from anysoar.models.objects import (
    Enrichment,
    FindingInfo,
    Group,
    Metadata,
    Note,
    Observable,
    Product,
    Reputation,
    User,
)

Alert = DetectionFinding
Case = IncidentFinding

__all__ = [
    "OCSF_VERSION",
    "ActivityId",
    "Alert",
    "Case",
    "ConfidenceId",
    "DetectionFinding",
    "DetectionFindingStatusId",
    "Enrichment",
    "FindingInfo",
    "Group",
    "ImpactId",
    "IncidentFinding",
    "IncidentFindingStatusId",
    "Metadata",
    "Note",
    "Observable",
    "ObservableTypeId",
    "OcsfModel",
    "PriorityId",
    "Product",
    "Reputation",
    "ReputationScoreId",
    "SeverityId",
    "Timestamp",
    "User",
    "UserTypeId",
    "VerdictId",
    "from_timestamp",
    "now_timestamp",
    "to_timestamp",
]
