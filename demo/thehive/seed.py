"""Load anysoar's synthetic phishing scenario into the local TheHive lab.

    uv run demo/thehive/seed.py

Creates the mock driver's eight alerts, with their indicators as observables, and its three
cases, each made from its alerts the way an analyst would: the case's first alert is
turned into the case and the others are merged into it. The scenario's notes become
comments and its closed case is closed with its verdict. Alerts that are not part of a case
keep their status (suppressed ones are Ignored). Re-running deletes the previous run's
alerts and cases first, so case numbers change each time.

Everything is synthetic: example.com/.net/.org addresses and RFC 5737 IP ranges.

Reads THEHIVE_URL and THEHIVE_API_KEY, or demo/thehive/.env.local written by up.sh.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from anysoar.drivers.mock import seed
from anysoar.drivers.thehive.alerts import OBSERVABLE_TYPES
from anysoar.drivers.thehive.cases import closing
from anysoar.models import (
    DetectionFinding,
    DetectionFindingStatusId,
    IncidentFinding,
    IncidentFindingStatusId,
    ObservableTypeId,
    SeverityId,
)

LAB = Path(__file__).resolve().parent
SOURCE = "anysoar-lab"
"""Marks the alerts this script creates, so a re-run can find and delete them."""

_DATA_TYPES: dict[ObservableTypeId, str] = {}
for _data_type, _ocsf in OBSERVABLE_TYPES.items():
    _DATA_TYPES.setdefault(_ocsf, _data_type)  # the first is TheHive's usual type

_SEVERITIES = {
    SeverityId.INFORMATIONAL: 1,
    SeverityId.LOW: 1,
    SeverityId.MEDIUM: 2,
    SeverityId.HIGH: 3,
    SeverityId.CRITICAL: 4,
}

_ALERT_STATUSES = {
    DetectionFindingStatusId.NEW: "New",
    DetectionFindingStatusId.IN_PROGRESS: "InProgress",
    DetectionFindingStatusId.SUPPRESSED: "Ignored",
    DetectionFindingStatusId.RESOLVED: "FalsePositive",
}


def settings() -> tuple[str, str]:
    url, key = os.environ.get("THEHIVE_URL"), os.environ.get("THEHIVE_API_KEY")
    env_file = LAB / ".env.local"
    if not key and env_file.exists():
        values = dict(
            line.split("=", 1) for line in env_file.read_text().splitlines() if "=" in line
        )
        key = values.get("THEHIVE_API_KEY")
    if not key:
        sys.exit("seed.py: set THEHIVE_API_KEY or run ./up.sh first")
    return (url or "http://127.0.0.1:9000").rstrip("/"), key


class TheHive:
    def __init__(self, url: str, key: str) -> None:
        self.url = url
        self.headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.url + urllib.parse.quote(path), data=data, headers=self.headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            sys.exit(f"seed.py: {method} {path} failed: {exc.code} {exc.read().decode()[:200]}")
        return json.loads(raw) if raw else None

    def query(self, *operations: dict[str, Any]) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = self.call("POST", "/api/v1/query", {"query": operations})
        return found


def reset(thehive: TheHive) -> None:
    """Delete what earlier runs created: the lab's alerts and the cases made from them."""
    alerts = thehive.query(
        {"_name": "listAlert"},
        {"_name": "filter", "_eq": {"_field": "source", "_value": SOURCE}},
    )
    for case_id in {a["caseId"] for a in alerts if a.get("caseId")}:
        thehive.call("DELETE", f"/api/v1/case/{case_id}")
    for alert in alerts:
        thehive.call("DELETE", f"/api/v1/alert/{alert['_id']}")


def create_alert(thehive: TheHive, alert: DetectionFinding, *, in_case: bool) -> dict[str, Any]:
    """Create an alert. Alerts in a case keep TheHive's status for that, Imported."""
    info = alert.finding_info
    observables = [
        {
            "dataType": _DATA_TYPES[o.type_id],
            "data": o.value,
            **({"message": o.name} if o.name else {}),
        }
        for o in alert.observables
        if o.type_id in _DATA_TYPES and o.value
    ]
    created: dict[str, Any] = thehive.call(
        "POST",
        "/api/v1/alert",
        {
            "type": "phishing-report",
            "source": SOURCE,
            "sourceRef": info.uid,
            "title": info.title,
            "description": info.desc or info.title,
            "severity": _SEVERITIES.get(alert.severity_id, 2),
            "date": info.created_time or alert.time,
            "tags": info.types,
            "observables": observables,
        },
    )
    status = _ALERT_STATUSES.get(alert.status_id or DetectionFindingStatusId.NEW, "New")
    if status != "New" and not in_case:
        thehive.call("PATCH", f"/api/v1/alert/{created['_id']}", {"status": status})
    return created


def wait_for_import(thehive: TheHive, case_id: str) -> None:
    """TheHive copies alerts' observables into a case in the background, and titles the
    case "[Import in progress: ...]" until it is done."""
    for _ in range(60):
        if not thehive.call("GET", f"/api/v1/case/{case_id}")["title"].startswith("[Import"):
            return
        time.sleep(1)
    sys.exit(f"seed.py: TheHive is still importing alerts into case {case_id}")


def create_case(thehive: TheHive, case: IncidentFinding, alert_ids: dict[str, str]) -> Any:
    first, *others = [alert_ids[f.uid] for f in case.finding_info_list]
    created = thehive.call("POST", f"/api/v1/alert/{first}/case", {})
    for alert_id in others:
        thehive.call("POST", f"/api/v1/alert/{alert_id}/merge/{created['_id']}")
    wait_for_import(thehive, created["_id"])
    update: dict[str, Any] = {
        "title": case.message,
        "description": case.desc or case.message,
        "severity": _SEVERITIES.get(case.severity_id, 2),
        "tags": ["Phishing", SOURCE],
    }
    if case.status_id is IncidentFindingStatusId.IN_PROGRESS:
        update["status"] = "InProgress"
    thehive.call("PATCH", f"/api/v1/case/{created['_id']}", update)
    for note in case.notes:
        # TheHive writes every comment as the API key's user; say whose note it was.
        author = note.owner.name if note.owner and note.owner.name else "analyst"
        thehive.call(
            "POST",
            f"/api/v1/case/{created['_id']}/comment",
            {"message": f"{author}: {note.comment}"},
        )
    closed = (IncidentFindingStatusId.RESOLVED, IncidentFindingStatusId.CLOSED)
    if case.status_id in closed and case.verdict_id is not None:
        status, tags = closing(case.verdict_id, update["tags"])
        close: dict[str, Any] = {"status": status, "tags": tags}
        if case.comment:
            close["summary"] = case.comment
        thehive.call("PATCH", f"/api/v1/case/{created['_id']}", close)
    return thehive.call("GET", f"/api/v1/case/{created['_id']}")


def main() -> None:
    thehive = TheHive(*settings())
    reset(thehive)
    alerts = seed.build_alerts()
    cases = seed.build_cases(alerts)
    in_cases = {f.uid for c in cases for f in c.finding_info_list}
    # Oldest first, so TheHive's creation order matches the scenario's.
    alert_ids = {}
    for alert in sorted(alerts, key=lambda a: a.finding_info.created_time or a.time):
        uid = alert.finding_info.uid
        alert_ids[uid] = create_alert(thehive, alert, in_case=uid in in_cases)["_id"]
    created = [create_case(thehive, c, alert_ids) for c in cases]

    print("Alerts:")
    for alert in alerts:
        where = " (in a case)" if alert.finding_info.uid in in_cases else ""
        print(f"  {alert_ids[alert.finding_info.uid]:<10} {alert.finding_info.title}{where}")
    print("\nCases:")
    for case in created:
        print(f"  #{case['number']:<4} {case['status']:<12} {case['title']}")
    print(
        "\nTriage one with the reference agent:\n"
        "  export THEHIVE_URL=http://127.0.0.1:9000\n"
        '  export THEHIVE_API_KEY="$(grep ^THEHIVE_API_KEY= demo/thehive/.env.local'
        ' | cut -d= -f2)"\n'
        f"  uv run anysoar-agent triage {created[1]['number']} --server-arg=--driver=thehive"
    )


if __name__ == "__main__":
    main()
