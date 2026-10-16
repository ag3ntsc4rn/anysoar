"""An in-memory stand-in for TheHive's REST API (v1), for tests.

Response shapes follow a TheHive 5.8 instance (the lab in demo/thehive): ids look like
``~8200``, times are milliseconds since the epoch, errors are ``{"type", "message"}``, and
lists come from ``POST /api/v1/query``, of which this fake understands the operations and
filters the driver uses.
"""

from __future__ import annotations

import functools
import itertools
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx2

# Fake credentials, derived so no key-like literal sits in the source.
API_KEY = uuid.uuid5(uuid.NAMESPACE_URL, "https://thehive.test/fake-api-key").hex
BASE_URL = "http://thehive.test:9000"

T0 = 1790845200000  # 2026-10-01T09:00:00Z
MINUTE = 60_000

_STAGES = {
    "New": "New",
    "InProgress": "InProgress",
    "Pending": "InProgress",
    "Imported": "Imported",
    "FalsePositive": "Closed",
    "Duplicate": "Closed",
    "Ignored": "Closed",
}
"""TheHive 5.8's built-in alert statuses and their stages."""


@dataclass
class FakeTheHive:
    alerts: dict[str, dict[str, Any]] = field(default_factory=dict)
    observables: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    requests: list[httpx2.Request] = field(default_factory=list)
    _ids: itertools.count[int] = field(default_factory=lambda: itertools.count(8200, 8))

    def __post_init__(self) -> None:
        self.phishing = self.alert(
            "Reported phishing: invoice from it-support@example.net",
            minutes=30,
            severity=3,
            tags=["phishing"],
            observables=(
                ("mail", "it-support@example.net"),
                ("url", "https://login.example.org/invoice"),
                ("ip", "198.51.100.23"),
            ),
        )
        self.scan = self.alert("Port scan from 203.0.113.9", minutes=20, severity=1)
        self.triaging = self.alert(
            "Impossible travel", minutes=10, severity=2, status="InProgress", assignee=True
        )
        self.dismissed = self.alert("Test alert", minutes=5, severity=1, status="Ignored")
        self.false_alarm = self.alert(
            "Malware download", minutes=0, severity=4, status="FalsePositive"
        )

    def next_id(self) -> str:
        return f"~{next(self._ids)}"

    def alert(
        self,
        title: str,
        *,
        minutes: int,
        severity: int = 2,
        status: str = "New",
        tags: list[str] | None = None,
        assignee: bool = False,
        observables: tuple[tuple[str, str], ...] = (),
    ) -> str:
        """Add an alert, created ``minutes`` after T0, as TheHive returns it. Returns its id."""
        alert_id = self.next_id()
        created = T0 + minutes * MINUTE
        self.alerts[alert_id] = {
            "_id": alert_id,
            "_type": "Alert",
            "_createdBy": "anysoar@anysoar.lab",
            "_createdAt": created,
            "_updatedAt": created + MINUTE,
            "type": "external",
            "source": "mail-gateway",
            "sourceRef": f"ref-{alert_id[1:]}",
            "externalLink": f"https://gateway.example.com/events/{alert_id[1:]}",
            "title": title,
            "description": f"Synthetic alert: {title}.",
            "severity": severity,
            "severityLabel": {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[severity],
            "date": created - 2 * MINUTE,
            "tags": tags or [],
            "tlp": 2,
            "tlpLabel": "AMBER",
            "pap": 2,
            "papLabel": "AMBER",
            "follow": True,
            "customFields": [],
            "observableCount": len(observables),
            "status": status,
            "stage": _STAGES[status],
            **({"assignee": "robin@example.com"} if assignee else {}),
            "extraData": {},
        }
        self.observables[alert_id] = [
            {
                "_id": self.next_id(),
                "_type": "Observable",
                "_createdAt": created + i,
                "dataType": data_type,
                "data": data,
                "tlp": 2,
                "pap": 2,
                "tags": [],
                "ioc": False,
                "sighted": False,
                "reports": {},
                "extraData": {},
            }
            for i, (data_type, data) in enumerate(observables)
        ]
        return alert_id

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path, method = request.url.path, request.method
        if path == "/api/status":
            return _json(200, {"versions": {"TheHive": "5.8.1-1"}, "config": {}})
        if request.headers.get("Authorization") != f"Bearer {API_KEY}":
            return _json(401, {"type": "AuthenticationError", "message": "Authentication failure"})
        if method == "GET" and (match := re.fullmatch(r"/api/v1/alert/(.+)", path)):
            alert = self.alerts.get(match[1])
            return _json(200, alert) if alert else _not_found("Alert")
        if method == "POST" and path == "/api/v1/query":
            return _json(200, self._query(json.loads(request.content)["query"]))
        return _json(404, {"type": "NotFoundError", "message": f"{method} {path}"})

    def _query(self, operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        first, *rest = operations
        if first["_name"] == "listAlert":
            items = list(self.alerts.values())
        elif first["_name"] == "getAlert" and rest and rest[0]["_name"] == "observables":
            items = list(self.observables.get(first["idOrName"], []))
            rest = rest[1:]
        else:
            raise AssertionError(f"the fake does not support the query {operations}")
        for op in rest:
            if op["_name"] == "filter":
                condition = {k: v for k, v in op.items() if k != "_name"}
                items = [i for i in items if _matches(i, condition)]
            elif op["_name"] == "sort":
                for spec in reversed(op["_fields"]):
                    ((name, order),) = spec.items()
                    items.sort(key=functools.partial(_sort_key, name=name), reverse=order == "desc")
            elif op["_name"] == "page":
                items = items[op["from"] : op["to"]]
            else:
                raise AssertionError(f"the fake does not support {op['_name']}")
        return items


def _sort_key(item: dict[str, Any], name: str) -> Any:
    value = item.get(name)
    if name == "_id":
        return int(str(value)[1:])  # TheHive orders ids numerically
    return value


def _matches(item: dict[str, Any], condition: dict[str, Any]) -> bool:
    ((op, arg),) = condition.items()
    if op == "_and":
        return all(_matches(item, c) for c in arg)
    if op == "_or":
        return any(_matches(item, c) for c in arg)
    if op == "_not":
        return not _matches(item, arg)
    value = item.get(arg["_field"])
    if op == "_eq":
        return bool(value == arg["_value"])
    if op == "_in":
        return value in arg["_values"]
    if op == "_gte":
        return value is not None and value >= arg["_value"]
    if op == "_lt":
        return value is not None and value < arg["_value"]
    raise AssertionError(f"the fake does not support the filter {op}")


def _not_found(kind: str) -> httpx2.Response:
    return _json(404, {"type": "NotFoundError", "message": f"{kind} not found"})


def _json(status: int, body: Any) -> httpx2.Response:
    return httpx2.Response(status, json=body)
