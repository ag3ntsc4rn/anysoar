"""Approve actions through an approval service over HTTP, e.g. a web console or a chat bot.

The service implements three endpoints, authenticated with ``Authorization: Bearer <token>``:

``POST /api/approvals``
    Body ``{"action": <Action as JSON>, "actor": <who is acting or null>}``. Returns
    ``201`` and ``{"id": "<approval id>"}``.

``GET /api/approvals/<id>?wait=<seconds>``
    Returns ``{"status": "pending" | "approved" | "rejected", "approver": str | null,
    "reason": str | null}``. The service may hold the request up to ``wait`` seconds until
    the status changes.

``POST /api/approvals/<id>/expire``
    Tells the service nobody is waiting for the decision any more (the policy layer timed
    out). Best effort.

The token only lets a client *ask* for approval. Deciding is the service's business, e.g. a
signed-in human in a browser; it must never be possible with this token, or the agent's side
could approve its own actions.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import urllib.error
import urllib.request
from typing import Any

from anysoar.policy.approval import Approval, ApprovalUnavailableError
from anysoar.policy.audit import audit_actor
from anysoar.policy.rules import Action

__all__ = ["HttpApprover"]


class HttpApprover:
    """Asks an approval service over HTTP and waits for a human's decision.

    Uses only the standard library, in a worker thread. If the service cannot be reached
    or rejects the token, the action is denied (:class:`ApprovalUnavailableError`). There is
    no overall timeout here: the policy layer's ``approval_timeout`` applies, and when it
    expires the service is told so.

    Args:
        url: The service's base address, e.g. ``http://127.0.0.1:8765``.
        token: A token that lets this client submit approval requests.
        poll_wait: Seconds each status request may wait at the service.
    """

    def __init__(self, url: str, token: str, *, poll_wait: float = 25.0) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self.poll_wait = poll_wait

    async def request_approval(self, action: Action) -> Approval:
        body = {"action": action.model_dump(mode="json"), "actor": audit_actor.get()}
        created = await self._call("POST", "/api/approvals", body)
        approval_id = created.get("id")
        if not isinstance(approval_id, str):
            raise ApprovalUnavailableError("approval service returned no approval id")
        try:
            while True:
                state = await self._call(
                    "GET", f"/api/approvals/{approval_id}?wait={self.poll_wait:g}"
                )
                status = state.get("status")
                if status in ("approved", "rejected"):
                    return Approval(
                        approved=status == "approved",
                        approver=state.get("approver"),
                        reason=state.get("reason"),
                    )
                if status != "pending":
                    raise ApprovalUnavailableError(f"approval {approval_id} is {status!r}")
        except asyncio.CancelledError:
            await self._expire(approval_id)
            raise

    async def _expire(self, approval_id: str) -> None:
        # Best effort, and never let it stop the cancellation the caller re-raises.
        with contextlib.suppress(ApprovalUnavailableError, asyncio.CancelledError):
            await asyncio.shield(self._call("POST", f"/api/approvals/{approval_id}/expire", {}))

    async def _call(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        timeout = self.poll_wait + 10
        return await asyncio.to_thread(self._call_sync, method, path, body, timeout)

    def _call_sync(self, method: str, path: str, body: Any, timeout: float) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.url + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise ApprovalUnavailableError("approval service rejected the token") from exc
            raise ApprovalUnavailableError(f"approval service error {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ApprovalUnavailableError(f"approval service unreachable at {self.url}") from exc
        except ValueError as exc:
            raise ApprovalUnavailableError("approval service sent invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ApprovalUnavailableError("approval service sent an unexpected response")
        return payload
