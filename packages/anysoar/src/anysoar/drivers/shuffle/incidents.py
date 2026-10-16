"""Shuffle incidents as anysoar cases.

Shuffle keeps incidents in its datastore (category ``shuffle-security_incidents``) as JSON
records that its Shuffle Security UI reads and writes. They are modelled on OCSF 2005
Incident Finding but differ from it; this module translates both ways. Observed on Shuffle
2.3.0 by editing an incident in the UI:

- Status ids are 1 New, 2 In Progress, 3 Resolved, 4 Closed (OCSF: 3 On Hold, 4 Resolved,
  5 Closed).
- Comments and status changes are entries in an ``activity`` list, newest last:
  ``{"id", "type": "comment" | "status", "user", "timestamp", "content", ...}``.
- There is no verdict field: the UI writes it into the status entry, e.g.
  ``"Resolved: True Positive - Risk Accepted"``. anysoar also stores OCSF ``verdict_id``.
- ``assignee`` is a plain string; findings are in ``finding_info_list`` or ``finding_info``.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from anysoar.models import (
    ActivityId,
    FindingInfo,
    IncidentFinding,
    IncidentFindingStatusId,
    Metadata,
    Note,
    Observable,
    Product,
    SeverityId,
    User,
    VerdictId,
)

__all__ = [
    "CATEGORY",
    "close_record",
    "comment_entry",
    "to_case",
    "verdict_label",
]

CATEGORY = "shuffle-security_incidents"
"""The datastore category Shuffle Security keeps incidents in."""

AUTHOR = "anysoar"
"""Who anysoar's comments and status changes are attributed to in Shuffle."""

PRODUCT = Product(name="Shuffle", vendor_name="Shuffle")

_STATUS_FROM_SHUFFLE = {
    1: IncidentFindingStatusId.NEW,
    2: IncidentFindingStatusId.IN_PROGRESS,
    3: IncidentFindingStatusId.RESOLVED,
    4: IncidentFindingStatusId.CLOSED,
}
SHUFFLE_CLOSED = (4, "Closed")


def verdict_label(verdict: VerdictId) -> str:
    """How Shuffle's UI names a verdict, e.g. ``True Positive``."""
    return verdict.name.replace("_", " ").title()


def _verdict_from_label(text: str) -> VerdictId | None:
    """The verdict in a status entry such as ``Resolved: True Positive - Risk Accepted``."""
    if ":" not in text:
        return None
    label = text.split(":", 1)[1].split(" - ", 1)[0].strip()
    try:
        return VerdictId[label.upper().replace(" ", "_")]
    except KeyError:
        return None


def comment_entry(text: str, timestamp: int, *, author: str = AUTHOR) -> dict[str, Any]:
    """An activity entry for a comment, as Shuffle Security writes it.

    ``ai_handled`` is set because anysoar's comments come from AI agents.
    """
    return {
        "id": f"comment-{timestamp}",
        "type": "comment",
        "user": author,
        "timestamp": timestamp,
        "content": text,
        "details": {},
        "attachments": [],
        "ai_handled": True,
    }


def close_record(
    record: dict[str, Any], verdict: VerdictId, comment: str | None, timestamp: int
) -> dict[str, Any]:
    """The record closed with ``verdict``, readable by both Shuffle's UI and anysoar."""
    closed = dict(record)
    closed["status_id"], closed["status"] = SHUFFLE_CLOSED
    closed["verdict_id"] = int(verdict)
    closed["verdict"] = verdict_label(verdict)
    closed["end_time"] = timestamp
    activity = list(record.get("activity") or [])
    activity.append(
        {
            "id": f"status-{timestamp}",
            "type": "status",
            "user": AUTHOR,
            "timestamp": timestamp,
            "content": f"Closed: {verdict_label(verdict)}",
            "details": {},
            "attachments": [],
        }
    )
    if comment:
        closed["comment"] = comment
        activity.append(comment_entry(comment, timestamp + 1))
    closed["activity"] = activity
    return closed


def to_case(record: dict[str, Any]) -> IncidentFinding:
    """An anysoar case from a Shuffle incident record."""
    uid = str(record["id"])
    activity = [a for a in record.get("activity") or [] if isinstance(a, dict)]
    status_id = _STATUS_FROM_SHUFFLE.get(record.get("status_id", 0), IncidentFindingStatusId.OTHER)
    closed = status_id in (IncidentFindingStatusId.RESOLVED, IncidentFindingStatusId.CLOSED)

    verdict = None
    if isinstance(record.get("verdict_id"), int):
        verdict = VerdictId(record["verdict_id"])
    else:
        for entry in reversed(activity):
            if entry.get("type") == "status":
                verdict = _verdict_from_label(str(entry.get("content", "")))
                break

    infos = record.get("finding_info_list") or (
        [record["finding_info"]] if record.get("finding_info") else []
    )
    title = record.get("title") or (infos[0].get("title") if infos else None)
    if not infos:
        # anysoar requires at least one finding; describe the incident itself (ADR 0001).
        infos = [{"uid": uid, "title": title}]

    assignee = record.get("assignee")
    return IncidentFinding(
        activity_id=ActivityId.CLOSE if closed else ActivityId.UPDATE,
        severity_id=_severity(record.get("severity_id")),
        status_id=status_id,
        status=record.get("status"),
        time=int(record.get("time") or 0),
        end_time=record.get("end_time"),
        message=title,
        desc=(infos[0].get("desc") if infos else None) or record.get("desc"),
        comment=record.get("comment"),
        verdict_id=verdict,
        metadata=Metadata(product=PRODUCT.model_copy(), uid=uid),
        finding_info_list=[FindingInfo.model_validate(i) for i in infos],
        observables=_observables(record),
        notes=[_note(a) for a in activity if a.get("type") == "comment"],
        assignee=_user(assignee) if isinstance(assignee, str) and assignee else None,
    )


def _severity(value: Any) -> SeverityId:
    try:
        return SeverityId(value)
    except ValueError:
        return SeverityId.UNKNOWN


def _observables(record: dict[str, Any]) -> list[Observable]:
    extensions = (record.get("metadata") or {}).get("extensions") or {}
    raw = record.get("observables") or (extensions.get("custom_attributes") or {}).get(
        "observables"
    )
    observables = []
    for item in raw or []:
        try:
            observables.append(Observable.model_validate(item))
        except ValidationError:
            continue  # Shuffle accepts free-form entries; keep the ones OCSF can express
    return observables


def _note(entry: dict[str, Any]) -> Note:
    author = entry.get("user")
    return Note(
        uid=entry.get("id"),
        comment=str(entry.get("content", "")),
        owner=_user(author) if isinstance(author, str) and author else None,
        created_time=entry.get("timestamp"),
    )


def _user(name: str) -> User:
    return User(name=name, email_addr=name if "@" in name else None)
