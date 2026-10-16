"""Tines cases as anysoar cases.

Tines cases (API v2) are not OCSF records; this module translates them to OCSF 2005
Incident Findings. The differences, from Tines' API reference:

- Status is ``OPEN`` or ``CLOSED``, refined by a team-defined sub-status such as "To do" or
  "In progress". The OCSF status is read from the sub-status name when it says something
  OCSF has a word for (in progress, on hold, resolved), and is otherwise New or Closed.
- There is no verdict field. anysoar records the verdict as a case tag, ``verdict:<name>``
  (e.g. ``verdict:false_positive``), which shows in Tines' UI and survives edits there.
- Comments are ``COMMENTED`` activities. Several people can be assigned; OCSF has one
  assignee, the first.
- Times are ISO 8601 strings; case ids are integers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from anysoar.models import (
    ActivityId,
    FindingInfo,
    IncidentFinding,
    IncidentFindingStatusId,
    Metadata,
    Note,
    Product,
    SeverityId,
    User,
    VerdictId,
    to_timestamp,
)

__all__ = [
    "VERDICT_TAG_PREFIX",
    "tag_names",
    "timestamp",
    "to_case",
    "to_note",
    "to_user",
    "verdict_label",
    "verdict_tag",
]

PRODUCT = Product(name="Tines", vendor_name="Tines")

VERDICT_TAG_PREFIX = "verdict:"
"""Prefix of the case tag that records a case's verdict."""

_SEVERITIES = {
    "CRITICAL": SeverityId.CRITICAL,
    "HIGH": SeverityId.HIGH,
    "MEDIUM": SeverityId.MEDIUM,
    "LOW": SeverityId.LOW,
    "INFO": SeverityId.INFORMATIONAL,
}

# Words in a sub-status name that map an open case to a more specific OCSF status.
_OPEN_SUB_STATUSES = (
    ("progress", IncidentFindingStatusId.IN_PROGRESS),
    ("investigat", IncidentFindingStatusId.IN_PROGRESS),
    ("hold", IncidentFindingStatusId.ON_HOLD),
    ("waiting", IncidentFindingStatusId.ON_HOLD),
    ("blocked", IncidentFindingStatusId.ON_HOLD),
)


def verdict_tag(verdict: VerdictId) -> str:
    """The case tag recording ``verdict``, e.g. ``verdict:false_positive``."""
    return f"{VERDICT_TAG_PREFIX}{verdict.name.lower()}"


def verdict_label(verdict: VerdictId) -> str:
    """A verdict for people to read, e.g. ``False Positive``."""
    return verdict.name.replace("_", " ").title()


def _verdict(tags: list[str]) -> VerdictId | None:
    for tag in reversed(tags):
        if tag.startswith(VERDICT_TAG_PREFIX):
            try:
                return VerdictId[tag.removeprefix(VERDICT_TAG_PREFIX).upper()]
            except KeyError:
                continue
    return None


def tag_names(case: dict[str, Any]) -> list[str]:
    return [t["name"] for t in case.get("tags") or [] if isinstance(t, dict) and t.get("name")]


def timestamp(value: Any) -> int | None:
    """Milliseconds since the epoch from a Tines ISO 8601 time, or None if unset."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return to_timestamp(datetime.fromisoformat(value))
    except ValueError:
        return None


def _status(case: dict[str, Any]) -> tuple[IncidentFindingStatusId, str | None]:
    sub_status = (case.get("sub_status") or {}).get("name")
    status = str(case.get("status") or "").upper()
    words = (sub_status or "").lower()
    if status == "CLOSED":
        resolved = "resolved" in words
        ocsf = IncidentFindingStatusId.RESOLVED if resolved else IncidentFindingStatusId.CLOSED
        return ocsf, sub_status or "Closed"
    if status == "OPEN":
        for word, ocsf in _OPEN_SUB_STATUSES:
            if word in words:
                return ocsf, sub_status
        return IncidentFindingStatusId.NEW, sub_status or "Open"
    return IncidentFindingStatusId.OTHER, sub_status or case.get("status")


def to_note(comment: dict[str, Any]) -> Note:
    """An anysoar note from a Tines ``COMMENTED`` activity or comment."""
    return Note(
        uid=str(comment["id"]),
        comment=str(comment.get("value") or ""),
        owner=to_user(comment.get("user")),
        created_time=timestamp(comment.get("created_at")),
    )


def to_user(user: Any) -> User | None:
    if not isinstance(user, dict):
        return None
    name = " ".join(str(user[k]) for k in ("first_name", "last_name") if user.get(k)) or None
    email = user.get("email") or None
    uid = user.get("user_id")
    if not (name or email or uid):
        return None
    return User(
        uid=str(uid) if uid is not None else None,
        name=name or email,
        email_addr=email,
    )


def to_case(case: dict[str, Any], comments: list[dict[str, Any]] | None = None) -> IncidentFinding:
    """An anysoar case from a Tines case.

    ``comments`` are the case's comments when fetched separately; otherwise the comments
    among the activities Tines embeds in the case (its first page of activities) are used.
    """
    uid = str(case["case_id"])
    status_id, status = _status(case)
    closed = status_id in (IncidentFindingStatusId.RESOLVED, IncidentFindingStatusId.CLOSED)
    tags = tag_names(case)
    if comments is None:
        comments = [
            a
            for a in case.get("activities") or []
            if isinstance(a, dict) and str(a.get("activity_type", "")).upper() == "COMMENTED"
        ]
    created = timestamp(case.get("created_at"))
    updated = timestamp(case.get("updated_at"))
    assignees = [u for u in map(to_user, case.get("assignees") or []) if u is not None]
    return IncidentFinding(
        activity_id=ActivityId.CLOSE if closed else ActivityId.UPDATE,
        severity_id=_SEVERITIES.get(str(case.get("priority") or "").upper(), SeverityId.UNKNOWN),
        status_id=status_id,
        status=status,
        time=updated or created or 0,
        end_time=timestamp(case.get("resolved_at")) if closed else None,
        message=case.get("name"),
        desc=case.get("description") or None,
        verdict_id=_verdict(tags),
        metadata=Metadata(product=PRODUCT.model_copy(), uid=uid),
        finding_info_list=[
            FindingInfo(
                uid=uid,
                title=case.get("name"),
                desc=case.get("description") or None,
                types=[t for t in tags if not t.startswith(VERDICT_TAG_PREFIX)],
                created_time=created,
                modified_time=updated,
                src_url=case.get("url") or None,
            )
        ],
        notes=[to_note(c) for c in comments],
        assignee=assignees[0] if assignees else None,
    )
