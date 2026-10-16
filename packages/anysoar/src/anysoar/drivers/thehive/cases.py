"""TheHive cases as anysoar cases.

TheHive cases (API v1) are not OCSF records; this module translates them to OCSF 2005
Incident Findings. The differences, from TheHive's API and a TheHive 5.8 instance:

- As with alerts, each status belongs to a fixed stage: New, InProgress or Closed. A case is
  closed by giving it a closing status, which is also its verdict: TruePositive,
  FalsePositive, Indeterminate, Duplicated or Other. Duplicated cases are OCSF Closed; other
  closed cases are Resolved. Verdicts no closing status names (e.g. Benign) are closed as
  Other with a ``verdict:<name>`` tag, which takes precedence when reading.
- The closing summary is the case's ``summary``, the OCSF ``comment``.
- A case's number (``42``, shown as #42 in TheHive) is its anysoar uid.
- ``_updatedAt`` is unset until a case is first changed; comments do not change it.
"""

from __future__ import annotations

from typing import Any

from anysoar.drivers.thehive.alerts import PRODUCT, SEVERITIES, to_observable, to_user
from anysoar.models import (
    ActivityId,
    FindingInfo,
    IncidentFinding,
    IncidentFindingStatusId,
    Metadata,
    Note,
    SeverityId,
    VerdictId,
)

__all__ = [
    "VERDICT_TAG_PREFIX",
    "case_status_filter",
    "closing",
    "to_case",
    "to_note",
]

VERDICT_TAG_PREFIX = "verdict:"
"""Prefix of the case tag that records a verdict no closing status names."""

_DUPLICATED = "Duplicated"

_CLOSING_STATUSES = {
    VerdictId.TRUE_POSITIVE: "TruePositive",
    VerdictId.FALSE_POSITIVE: "FalsePositive",
    VerdictId.INSUFFICIENT_DATA: "Indeterminate",
    VerdictId.DUPLICATE: _DUPLICATED,
    VerdictId.OTHER: "Other",
}
"""TheHive's built-in closing statuses, by the verdict each records."""

_VERDICTS = {status: verdict for verdict, status in _CLOSING_STATUSES.items()}


def _stage_is(stage: str) -> dict[str, Any]:
    return {"_eq": {"_field": "stage", "_value": stage}}


_IS_DUPLICATED = {"_eq": {"_field": "status", "_value": _DUPLICATED}}
_STATUS_CLAUSES = {
    IncidentFindingStatusId.NEW: _stage_is("New"),
    IncidentFindingStatusId.IN_PROGRESS: _stage_is("InProgress"),
    IncidentFindingStatusId.RESOLVED: {"_and": [_stage_is("Closed"), {"_not": _IS_DUPLICATED}]},
    IncidentFindingStatusId.CLOSED: _IS_DUPLICATED,
}
"""Query filters for each OCSF status a case can have."""


def case_status_filter(status_ids: frozenset[IncidentFindingStatusId]) -> dict[str, Any]:
    """A query filter matching cases with any of the OCSF ``status_ids``; the inverse of the
    mapping in :func:`to_case`."""
    clauses = [_STATUS_CLAUSES[s] for s in sorted(status_ids) if s in _STATUS_CLAUSES]
    if not clauses:
        # No TheHive case has any of these statuses (e.g. On Hold).
        return {"_eq": {"_field": "stage", "_value": "anysoar:no-such-stage"}}
    return clauses[0] if len(clauses) == 1 else {"_or": clauses}


def closing(verdict: VerdictId, tags: list[str]) -> tuple[str, list[str]]:
    """The closing status and tags that record ``verdict`` on a case with ``tags``."""
    status = _CLOSING_STATUSES.get(verdict, "Other")
    kept = [t for t in tags if not t.startswith(VERDICT_TAG_PREFIX)]
    if verdict not in _CLOSING_STATUSES:
        kept.append(f"{VERDICT_TAG_PREFIX}{verdict.name.lower()}")
    return status, kept


def _status(case: dict[str, Any]) -> IncidentFindingStatusId:
    stage = case.get("stage")
    if stage == "New":
        return IncidentFindingStatusId.NEW
    if stage == "InProgress":
        return IncidentFindingStatusId.IN_PROGRESS
    if stage == "Closed":
        if case.get("status") == _DUPLICATED:
            return IncidentFindingStatusId.CLOSED
        return IncidentFindingStatusId.RESOLVED
    return IncidentFindingStatusId.OTHER


def _verdict(case: dict[str, Any], tags: list[str]) -> VerdictId | None:
    if case.get("stage") != "Closed":
        return None
    for tag in reversed(tags):
        if tag.startswith(VERDICT_TAG_PREFIX):
            try:
                return VerdictId[tag.removeprefix(VERDICT_TAG_PREFIX).upper()]
            except KeyError:
                continue
    return _VERDICTS.get(str(case.get("status")))


def to_note(comment: dict[str, Any]) -> Note:
    """An anysoar note from a TheHive case comment."""
    return Note(
        uid=str(comment["_id"]),
        comment=str(comment.get("message") or ""),
        owner=to_user(comment.get("createdBy")),
        created_time=comment.get("createdAt"),
        modified_time=comment.get("updatedAt"),
    )


def _finding_info(record: dict[str, Any], uid: str) -> FindingInfo:
    return FindingInfo(
        uid=uid,
        title=record.get("title"),
        desc=record.get("description") or None,
        types=[str(t) for t in record.get("tags") or [] if not t.startswith(VERDICT_TAG_PREFIX)],
        created_time=record.get("_createdAt"),
        modified_time=record.get("_updatedAt"),
    )


def to_case(
    case: dict[str, Any],
    *,
    comments: list[dict[str, Any]] | None = None,
    alerts: list[dict[str, Any]] | None = None,
    observables: list[dict[str, Any]] | None = None,
) -> IncidentFinding:
    """An anysoar case from a TheHive case.

    The findings it groups are the TheHive ``alerts`` it was made from, if fetched and any;
    otherwise the case itself.
    """
    uid = str(case["number"])
    status_id = _status(case)
    closed = case.get("stage") == "Closed"
    tags = [str(t) for t in case.get("tags") or []]
    created = case.get("_createdAt")
    updated = case.get("_updatedAt")
    infos = [_finding_info(a, str(a["_id"])) for a in alerts or []]
    return IncidentFinding(
        activity_id=ActivityId.CLOSE if closed else ActivityId.UPDATE,
        severity_id=SEVERITIES.get(case.get("severity"), SeverityId.UNKNOWN),  # type: ignore[arg-type]
        status_id=status_id,
        status=case.get("status"),
        time=updated or created or 0,
        start_time=case.get("startDate"),
        end_time=case.get("endDate") if closed else None,
        message=case.get("title"),
        desc=case.get("description") or None,
        comment=case.get("summary") or None,
        verdict_id=_verdict(case, tags),
        assignee=to_user(case.get("assignee")),
        metadata=Metadata(product=PRODUCT.model_copy(), uid=uid),
        finding_info_list=infos or [_finding_info(case, uid)],
        observables=[to_observable(o) for o in observables or []],
        notes=[to_note(c) for c in comments or []],
        unmapped={
            k: case[k]
            for k in ("_id", "impactStatus", "tlp", "pap", "flag")
            if case.get(k) is not None
        },
    )
