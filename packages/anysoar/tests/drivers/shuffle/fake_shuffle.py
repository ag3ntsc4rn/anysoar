"""An in-memory stand-in for Shuffle's REST API, for tests.

Response shapes and error quirks are copied from a real Shuffle 2.3.0 (demo/shuffle): lists
are bare JSON arrays, unset fields are null, a missing workflow is a 401 and a missing
execution a 400, both with ``{"success": false, "reason": ...}``.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx2

# Fake credentials, derived so no key-like literal sits in the source.
API_KEY = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://shuffle.test/fake-api-key"))
ORG_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://shuffle.test/fake-org"))
BASE_URL = "http://shuffle.test"


@dataclass
class Execution:
    workflow_id: str
    argument: str
    polls: int = 0
    fail_step: bool = False
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    authorization: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: int = field(default_factory=lambda: int(time.time()))


def workflow(name: str, *, tags: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "description": extra.pop("description", ""),
        "tags": tags,
        "is_valid": True,
        "input_questions": extra.pop("input_questions", None),
        "example_argument": "",
        "hidden": extra.pop("hidden", False),
        "org_id": ORG_ID,
        **extra,
    }


class FakeShuffle:
    """Handles requests like Shuffle would. Use :meth:`transport` with the driver."""

    def __init__(self) -> None:
        self.workflows: dict[str, dict[str, Any]] = {}
        self.executions: dict[str, Execution] = {}
        self.requests: list[httpx2.Request] = []
        self.failing_workflows: set[str] = set()
        for w in (
            workflow("Block sender", description="Block a sender at the mail gateway"),
            workflow(
                "Disable user account",
                tags=["anysoar:destructive", "iam"],
                description="Disable a directory account",
            ),
            workflow(
                "Block URL",
                input_questions=[
                    {"name": "url", "value": "", "required": True, "deleted": False},
                    {"name": "reason", "value": "", "required": False, "deleted": False},
                ],
            ),
            workflow("Internal helper", hidden=True),
        ):
            self.workflows[w["id"]] = w

    def by_name(self, name: str) -> dict[str, Any]:
        return next(w for w in self.workflows.values() if w["name"] == name)

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if request.headers.get("Authorization") != f"Bearer {API_KEY}":
            return _json(401, {"success": False})
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else {}

        if method == "GET" and path == "/api/v1/users/getinfo":
            return _json(
                200, {"username": "admin", "active_org": {"id": ORG_ID, "name": "default"}}
            )
        if method == "GET" and path == "/api/v1/workflows":
            return _json(200, list(self.workflows.values()))
        if match := re.fullmatch(r"/api/v1/workflows/([^/]+)/execute", path):
            return self._execute(match.group(1), body)
        if method == "POST" and path == "/api/v1/streams/results":
            return self._results(body)
        return _json(404, {"success": False, "reason": f"no route {method} {path}"})

    def _execute(self, workflow_id: str, body: dict[str, Any]) -> httpx2.Response:
        if len(workflow_id) != 36:
            return _json(401, {"success": False, "reason": "Workflow ID to execute is not valid"})
        if workflow_id not in self.workflows:
            reason = f"Workflow with ID {workflow_id} doesn't exist."
            return _json(401, {"success": False, "reason": reason})
        argument = body.get("execution_argument", "")
        if not isinstance(argument, str):
            # Real Shuffle: a non-string argument makes the whole body the argument.
            argument = json.dumps(body)
        ex = Execution(workflow_id, argument, fail_step=workflow_id in self.failing_workflows)
        self.executions[ex.id] = ex
        return _json(
            200, {"success": True, "execution_id": ex.id, "authorization": ex.authorization}
        )

    def _results(self, body: dict[str, Any]) -> httpx2.Response:
        ex = self.executions.get(body.get("execution_id", ""))
        if ex is None:
            reason = "Bad authorization key or execution_id might not exist."
            return _json(400, {"success": False, "reason": reason})
        ex.polls += 1
        finished = ex.polls > 1
        step_status = "FAILURE" if ex.fail_step else "SUCCESS"
        return _json(
            200,
            {
                "execution_id": ex.id,
                "authorization": ex.authorization,
                "workflow_id": ex.workflow_id,
                "execution_argument": ex.argument,
                "status": "FINISHED" if finished else "EXECUTING",
                "started_at": ex.started_at,
                "completed_at": ex.started_at + 5 if finished else 0,
                "result": ex.argument if finished else "",
                "results": [
                    {
                        "action": {"label": "echo", "app_name": "Shuffle Tools"},
                        "status": step_status if finished else "EXECUTING",
                        "result": ex.argument,
                    }
                ],
            },
        )


def _json(status: int, body: Any) -> httpx2.Response:
    return httpx2.Response(status, json=body)
