"""The Shuffle driver: Shuffle workflows as anysoar playbooks."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

import httpx2
from pydantic import JsonValue

from anysoar import __version__
from anysoar.drivers.shuffle.client import ShuffleAPIError, ShuffleClient
from anysoar.errors import NotFoundError
from anysoar.interface import (
    ActionTier,
    Driver,
    DriverInfo,
    Playbook,
    PlaybookRun,
    PlaybookRunStatus,
)
from anysoar.models import now_timestamp

__all__ = ["DESTRUCTIVE_TAG", "ShuffleDriver"]

DESTRUCTIVE_TAG = "anysoar:destructive"
"""Tag a Shuffle workflow with this to mark it as a destructive playbook."""

_RUN_STATUSES = {
    "EXECUTING": PlaybookRunStatus.RUNNING,
    # Waiting for user input or an approval inside Shuffle; still in progress.
    "WAITING": PlaybookRunStatus.RUNNING,
    "FINISHED": PlaybookRunStatus.SUCCEEDED,
    "SUCCESS": PlaybookRunStatus.SUCCEEDED,
    "ABORTED": PlaybookRunStatus.FAILED,
    "FAILURE": PlaybookRunStatus.FAILED,
    "FAILED": PlaybookRunStatus.FAILED,
}
_FAILED_STEP_STATUSES = {"FAILURE", "ABORTED"}


class ShuffleDriver(Driver):
    """Drives a Shuffle instance through its REST API.

    Playbooks are Shuffle workflows. A run's input is the workflow's execution argument: a
    JSON object of the ``inputs``, plus an ``anysoar`` object with the ``case_uid`` and
    ``alert_uid`` the run is for, which workflows read as ``$exec.<input>`` and
    ``$exec.anysoar.case_uid``. Shuffle has no notion of risk, so workflows are ``WRITE``
    tier unless tagged ``anysoar:destructive``.

    Args:
        base_url: Shuffle's address, e.g. ``http://127.0.0.1:5001``. Defaults to the
            ``SHUFFLE_URL`` environment variable.
        api_key: An API key from Shuffle's settings. Defaults to ``SHUFFLE_API_KEY``.
        timeout: Seconds to wait for each request.
        transport: An ``httpx2`` transport, for tests.
    """

    name = "shuffle"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        base_url = base_url or os.environ.get("SHUFFLE_URL")
        api_key = api_key or os.environ.get("SHUFFLE_API_KEY")
        if not base_url or not api_key:
            raise ValueError(
                "Shuffle needs a base_url and api_key (or SHUFFLE_URL and SHUFFLE_API_KEY)"
            )
        self._client = ShuffleClient(base_url, api_key, timeout=timeout, transport=transport)

    async def describe(self) -> DriverInfo:
        return DriverInfo(
            name=self.name,
            capabilities=self.implemented_capabilities(),
            driver_version=__version__,
            soar_product="Shuffle",
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- Playbooks ------------------------------------------------------------------------

    async def list_playbooks(self) -> list[Playbook]:
        workflows = await self._client.request(
            "GET", "/api/v1/workflows", params={"truncate": "false"}
        )
        return [_to_playbook(w) for w in workflows or [] if not w.get("hidden")]

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        argument: dict[str, Any] = dict(inputs or {})
        context = {"case_uid": case_uid, "alert_uid": alert_uid}
        if any(context.values()):
            argument["anysoar"] = {k: v for k, v in context.items() if v}
        try:
            started = await self._client.request(
                "POST",
                f"/api/v1/workflows/{playbook_uid}/execute",
                # Shuffle expects the argument as a string; an object would be ignored.
                json={"execution_argument": json.dumps(argument)},
            )
        except ShuffleAPIError as exc:
            raise _not_found_or(exc, "playbook", playbook_uid) from exc
        return PlaybookRun(
            uid=started["execution_id"],
            playbook_uid=playbook_uid,
            status=PlaybookRunStatus.QUEUED,
            started_time=now_timestamp(),
        )

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        try:
            # Authenticated with the API key, so Shuffle's per-run token is never needed.
            execution = await self._client.request(
                "POST", "/api/v1/streams/results", json={"execution_id": run_uid}
            )
        except ShuffleAPIError as exc:
            raise _not_found_or(exc, "playbook run", run_uid) from exc
        return _to_run(execution)


def _not_found_or(exc: ShuffleAPIError, kind: str, uid: str) -> Exception:
    return NotFoundError(kind, uid) if exc.is_not_found else exc


def _to_playbook(workflow: dict[str, Any]) -> Playbook:
    tags = workflow.get("tags") or []
    questions = [q for q in workflow.get("input_questions") or [] if not q.get("deleted")]
    schema: dict[str, JsonValue] | None = None
    if questions:
        schema = {
            "type": "object",
            "properties": {q["name"]: {"type": "string"} for q in questions},
            "required": [q["name"] for q in questions if q.get("required")],
        }
    return Playbook(
        uid=workflow["id"],
        name=workflow.get("name") or workflow["id"],
        description=workflow.get("description") or None,
        tier=ActionTier.DESTRUCTIVE if DESTRUCTIVE_TAG in tags else ActionTier.WRITE,
        input_schema=schema,
    )


def _seconds_to_ms(value: Any) -> int | None:
    return int(value) * 1000 if isinstance(value, int | float) and value > 0 else None


def _to_run(execution: dict[str, Any]) -> PlaybookRun:
    status = _RUN_STATUSES.get(execution.get("status", ""), PlaybookRunStatus.UNKNOWN)
    failed_steps = [
        (r.get("action") or {}).get("label") or "step"
        for r in execution.get("results") or []
        if r.get("status") in _FAILED_STEP_STATUSES
    ]
    message = None
    if status is PlaybookRunStatus.SUCCEEDED and failed_steps:
        # Shuffle finishes a workflow even when some of its steps fail.
        status = PlaybookRunStatus.FAILED
    if failed_steps:
        message = f"failed steps: {', '.join(failed_steps)}"
    outputs: dict[str, JsonValue] = {}
    result = execution.get("result")
    if status.is_finished and result:
        try:
            outputs["result"] = json.loads(result)
        except (TypeError, ValueError):
            outputs["result"] = result
    return PlaybookRun(
        uid=execution["execution_id"],
        playbook_uid=execution.get("workflow_id") or "",
        status=status,
        started_time=_seconds_to_ms(execution.get("started_at")),
        ended_time=_seconds_to_ms(execution.get("completed_at")),
        message=message,
        outputs=outputs,
    )
