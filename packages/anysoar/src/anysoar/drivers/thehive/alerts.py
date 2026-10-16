"""TheHive alerts and observables as anysoar alerts and indicators.

TheHive alerts (API v1) are not OCSF records; this module translates them to OCSF 2004
Detection Findings. The differences, from TheHive's API and a TheHive 5.8 instance:

- Each status belongs to one of four fixed *stages*: New, InProgress, Closed and Imported
  (the alert was turned into or merged with a case). Organisations can add statuses, so the
  OCSF status comes from the stage, except for the built-in closing statuses that say more:
  Ignored is Suppressed, and FalsePositive and Duplicate also set the verdict. Imported has
  no OCSF equivalent and is Other.
- Severity is 1 (low) to 4 (critical).
- ``_createdAt`` is when the alert reached TheHive (the OCSF ``created_time``, which anysoar
  filters and sorts on); ``date`` is when the source raised it (``first_seen_time``).
- Ids look like ``~8200``; the ``~`` is part of the id.
"""

from __future__ import annotations

from typing import Any

from anysoar.models import (
    ActivityId,
    DetectionFinding,
    DetectionFindingStatusId,
    FindingInfo,
    Metadata,
    Observable,
    ObservableTypeId,
    Product,
    SeverityId,
    User,
    VerdictId,
)

__all__ = [
    "OBSERVABLE_TYPES",
    "PRODUCT",
    "SEVERITIES",
    "alert_status_filter",
    "min_severity",
    "to_alert",
    "to_observable",
    "to_user",
]

PRODUCT = Product(name="TheHive", vendor_name="StrangeBee")

SEVERITIES = {
    1: SeverityId.LOW,
    2: SeverityId.MEDIUM,
    3: SeverityId.HIGH,
    4: SeverityId.CRITICAL,
}

_STAGES = {
    "New": DetectionFindingStatusId.NEW,
    "InProgress": DetectionFindingStatusId.IN_PROGRESS,
    "Closed": DetectionFindingStatusId.RESOLVED,
    "Imported": DetectionFindingStatusId.OTHER,
}

_SUPPRESSED = "Ignored"
"""The built-in closing status for alerts nobody needs to act on."""


def _stage_is(stage: str) -> dict[str, Any]:
    return {"_eq": {"_field": "stage", "_value": stage}}


_IS_SUPPRESSED = {"_eq": {"_field": "status", "_value": _SUPPRESSED}}
_STATUS_CLAUSES = {
    DetectionFindingStatusId.NEW: _stage_is("New"),
    DetectionFindingStatusId.IN_PROGRESS: _stage_is("InProgress"),
    DetectionFindingStatusId.SUPPRESSED: _IS_SUPPRESSED,
    DetectionFindingStatusId.RESOLVED: {"_and": [_stage_is("Closed"), {"_not": _IS_SUPPRESSED}]},
    DetectionFindingStatusId.OTHER: _stage_is("Imported"),
}
"""Query filters for each OCSF status an alert can have."""

_VERDICTS = {"FalsePositive": VerdictId.FALSE_POSITIVE, "Duplicate": VerdictId.DUPLICATE}

# TheHive's built-in observable types. OCSF has no domain type; hostnames cover domains.
OBSERVABLE_TYPES = {
    "ip": ObservableTypeId.IP_ADDRESS,
    "domain": ObservableTypeId.HOSTNAME,
    "fqdn": ObservableTypeId.HOSTNAME,
    "hostname": ObservableTypeId.HOSTNAME,
    "url": ObservableTypeId.URL_STRING,
    "mail": ObservableTypeId.EMAIL_ADDRESS,
    "mail-subject": ObservableTypeId.EMAIL_OBJECT_SUBJECT,
    "hash": ObservableTypeId.HASH,
    "filename": ObservableTypeId.FILE_NAME,
    "registry": ObservableTypeId.REGISTRY_KEY_PATH,
    "user-agent": ObservableTypeId.HTTP_USER_AGENT,
}


def _status(alert: dict[str, Any]) -> DetectionFindingStatusId:
    status = alert.get("status")
    if status == _SUPPRESSED:
        return DetectionFindingStatusId.SUPPRESSED
    return _STAGES.get(str(alert.get("stage")), DetectionFindingStatusId.OTHER)


def alert_status_filter(status_ids: frozenset[DetectionFindingStatusId]) -> dict[str, Any]:
    """A query filter matching alerts with any of the OCSF ``status_ids``; the inverse of the
    mapping in :func:`to_alert`."""
    clauses = [_STATUS_CLAUSES[s] for s in sorted(status_ids) if s in _STATUS_CLAUSES]
    if not clauses:
        # No TheHive alert has any of these statuses (e.g. Archived or Deleted).
        return {"_eq": {"_field": "stage", "_value": "anysoar:no-such-stage"}}
    return clauses[0] if len(clauses) == 1 else {"_or": clauses}


def min_severity(severity_id: SeverityId) -> int:
    """The lowest TheHive severity at or above the OCSF ``severity_id``."""
    for severity, ocsf in sorted(SEVERITIES.items()):
        if ocsf >= severity_id:
            return severity
    return max(SEVERITIES) + 1  # above critical: matches nothing


def to_user(login: Any) -> User | None:
    """A user from a TheHive login, which is usually an email address."""
    if not isinstance(login, str) or not login:
        return None
    return User(uid=login, name=login, email_addr=login if "@" in login else None)


def to_observable(observable: dict[str, Any]) -> Observable:
    """An anysoar indicator from a TheHive observable. File attachments have no value."""
    data_type = str(observable.get("dataType") or "")
    data = observable.get("data")
    return Observable(
        type_id=OBSERVABLE_TYPES.get(data_type, ObservableTypeId.OTHER),
        type=data_type or None,
        value=str(data) if data is not None else None,
    )


def to_alert(
    alert: dict[str, Any], observables: list[dict[str, Any]] | None = None
) -> DetectionFinding:
    """An anysoar alert from a TheHive alert, with ``observables`` if they were fetched."""
    uid = str(alert["_id"])
    created = alert.get("_createdAt")
    updated = alert.get("_updatedAt")
    status_id = _status(alert)
    closed = alert.get("stage") == "Closed"
    tags = [str(t) for t in alert.get("tags") or []]
    return DetectionFinding(
        activity_id=ActivityId.CLOSE if closed else ActivityId.UPDATE,
        severity_id=SEVERITIES.get(alert.get("severity"), SeverityId.UNKNOWN),  # type: ignore[arg-type]
        status_id=status_id,
        status=alert.get("status"),
        time=updated or created or 0,
        message=alert.get("title"),
        is_alert=True,
        verdict_id=_VERDICTS.get(str(alert.get("status"))),
        assignee=to_user(alert.get("assignee")),
        metadata=Metadata(product=PRODUCT.model_copy(), uid=uid),
        finding_info=FindingInfo(
            uid=uid,
            title=alert.get("title"),
            desc=alert.get("description") or None,
            types=[t for t in (alert.get("type"), *tags) if t],
            created_time=created,
            modified_time=updated,
            first_seen_time=alert.get("date"),
            src_url=alert.get("externalLink") or None,
        ),
        observables=[to_observable(o) for o in observables or []],
        unmapped={
            k: alert[k]
            for k in ("source", "sourceRef", "caseId", "tlp", "pap")
            if alert.get(k) is not None
        }
        or None,
    )
