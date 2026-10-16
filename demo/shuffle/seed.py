"""Load anysoar's synthetic phishing scenario into the local Shuffle lab.

    uv run demo/shuffle/seed.py

Creates the mock driver's three cases as Shuffle incidents, with ids derived from the mock's
uids so re-running resets them, and one stand-in workflow per mock playbook. The workflows
just echo their input (Shuffle Tools' repeat_back_to_me); "Disable user account" is tagged
anysoar:destructive. Everything is synthetic: example.com/.net/.org and RFC 5737 addresses.

Reads SHUFFLE_URL and SHUFFLE_API_KEY, or demo/shuffle/.env.local written by up.sh.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from anysoar.drivers.mock import seed
from anysoar.drivers.shuffle import DESTRUCTIVE_TAG
from anysoar.drivers.shuffle.incidents import CATEGORY, close_record, comment_entry
from anysoar.interface import ActionTier
from anysoar.models import IncidentFinding, IncidentFindingStatusId

LAB = Path(__file__).resolve().parent

_SHUFFLE_STATUS = {
    IncidentFindingStatusId.NEW: (1, "New"),
    IncidentFindingStatusId.IN_PROGRESS: (2, "In Progress"),
    IncidentFindingStatusId.ON_HOLD: (2, "In Progress"),  # Shuffle has no "on hold"
    IncidentFindingStatusId.RESOLVED: (3, "Resolved"),
    IncidentFindingStatusId.CLOSED: (4, "Closed"),
}


def incident_id(case_uid: str) -> str:
    """The Shuffle incident id for a mock case, the same on every run."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://anysoar.invalid/lab/{case_uid}"))


def settings() -> tuple[str, str]:
    url, key = os.environ.get("SHUFFLE_URL"), os.environ.get("SHUFFLE_API_KEY")
    env_file = LAB / ".env.local"
    if not key and env_file.exists():
        values = dict(
            line.split("=", 1) for line in env_file.read_text().splitlines() if "=" in line
        )
        key = values.get("SHUFFLE_API_KEY")
    if not key:
        sys.exit("seed.py: set SHUFFLE_API_KEY or run ./up.sh first")
    return (url or "http://127.0.0.1:5001").rstrip("/"), key


class Shuffle:
    def __init__(self, url: str, key: str) -> None:
        self.url = url
        self.headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.url + path, data=data, headers=self.headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            sys.exit(f"seed.py: {method} {path} failed: {exc.code} {exc.read().decode()[:200]}")
        return json.loads(raw) if raw else None


def to_record(case: IncidentFinding) -> dict[str, Any]:
    """A Shuffle incident record for a mock case, in the shape Shuffle Security writes."""
    assert case.metadata.uid is not None
    uid = incident_id(case.metadata.uid)
    findings = [f.model_dump(mode="json", exclude_none=True) for f in case.finding_info_list]
    status_id, status = _SHUFFLE_STATUS[case.status_id]
    record: dict[str, Any] = {
        "id": uid,
        "class_uid": 2005,
        "category_uid": 2,
        "time": case.start_time or case.time,
        "severity_id": int(case.severity_id),
        "severity": case.severity_id.name.title(),
        "status_id": status_id,
        "status": status,
        "title": case.message,
        "desc": case.desc,
        "types": ["Phishing"],
        "finding_info": {**findings[0], "desc": case.desc},
        "finding_info_list": findings,
        "observables": [o.to_ocsf() for o in case.observables],
        "assignee": case.assignee.email_addr or "" if case.assignee else "",
        "activity": [
            comment_entry(
                n.comment,
                n.created_time or case.time,
                author=n.owner.name if n.owner and n.owner.name else "anysoar",
                ai_handled=False,  # the scenario's notes are written by people
            )
            for n in case.notes
        ],
        "tasks": [],
        "metadata": {"extensions": {"custom_attributes": {"anysoar_scenario": "phishing"}}},
    }
    if case.status_id is IncidentFindingStatusId.CLOSED and case.verdict_id is not None:
        closer = case.assignee.name if case.assignee and case.assignee.name else "anysoar"
        record = close_record(
            record,
            case.verdict_id,
            case.comment,
            case.end_time or case.time,
            author=closer,
            ai_handled=False,
        )
    return record


def seed_incidents(shuffle: Shuffle, org: str) -> list[dict[str, Any]]:
    records = [to_record(c) for c in seed.build_cases(seed.build_alerts())]
    for record in records:
        shuffle.call(
            "POST",
            f"/api/v1/orgs/{org}/set_cache",
            {
                "key": record["id"],
                "category": CATEGORY,
                "value": json.dumps(record),
                "ignore_security_rules": True,
            },
        )
    return records


def seed_workflows(shuffle: Shuffle) -> list[dict[str, Any]]:
    existing = {w["name"]: w for w in shuffle.call("GET", "/api/v1/workflows?truncate=false") or []}
    workflows = []
    for playbook in seed.build_playbooks():
        workflow = existing.get(playbook.name)
        if workflow is None:
            workflow = shuffle.call(
                "POST",
                "/api/v1/workflows",
                {"name": playbook.name, "description": playbook.description or ""},
            )
            if not workflow.get("actions"):
                sys.exit("seed.py: Shuffle has not loaded its apps yet; wait and retry")
            # Shuffle starts a new workflow with one "repeat back to me" step: echo the input.
            step = workflow["actions"][0]
            step["parameters"] = [
                {**p, "value": "$exec"} if p.get("name") == "call" else p
                for p in step["parameters"]
            ]
        destructive = playbook.tier is ActionTier.DESTRUCTIVE
        workflow["tags"] = ["anysoar-lab", *([DESTRUCTIVE_TAG] if destructive else [])]
        workflow["description"] = f"{playbook.description} (lab stand-in: echoes its input)"
        saved = shuffle.call("PUT", f"/api/v1/workflows/{workflow['id']}", workflow)
        if saved.get("errors"):
            print(f"warning: {playbook.name}: {saved['errors']}")
        workflows.append(workflow)
    return workflows


def main() -> None:
    shuffle = Shuffle(*settings())
    org = shuffle.call("GET", "/api/v1/users/getinfo")["active_org"]["id"]
    workflows = seed_workflows(shuffle)
    records = seed_incidents(shuffle, org)

    print("Playbooks (Shuffle workflows):")
    for w in workflows:
        print(f"  {w['name']:<28} {', '.join(w['tags'])}")
    print("\nCases (Shuffle incidents):")
    for r in records:
        print(f"  {r['id']}  {r['status']:<12} {r['title']}")
    print(
        "\nTriage one with the reference agent:\n"
        "  export SHUFFLE_URL=http://127.0.0.1:5001\n"
        '  export SHUFFLE_API_KEY="$(grep ^SHUFFLE_API_KEY= demo/shuffle/.env.local'
        ' | cut -d= -f2)"\n'
        f"  uv run anysoar-agent triage {records[0]['id']} --server-arg=--driver=shuffle"
    )


if __name__ == "__main__":
    main()
