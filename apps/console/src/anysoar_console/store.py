"""In-memory state of the console: approval requests and a live event bus."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

__all__ = ["ApprovalRequest", "ApprovalStore", "EventBus"]

Status = Literal["pending", "approved", "rejected", "expired"]


def _now() -> int:
    return int(time.time() * 1000)


class EventBus:
    """Fans out events to every connected browser. Slow subscribers drop old events."""

    def __init__(self, queue_size: int = 500) -> None:
        self._queues: set[asyncio.Queue[dict[str, Any]]] = set()
        self._queue_size = queue_size

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        event = {"kind": kind, "time": _now(), "data": data}
        for queue in self._queues:
            if queue.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(event)

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(self._queue_size)
        self._queues.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._queues.discard(queue)


@dataclass
class ApprovalRequest:
    action: dict[str, Any]
    actor: str | None
    id: str = field(default_factory=lambda: secrets.token_urlsafe(12))
    created: int = field(default_factory=_now)
    status: Status = "pending"
    approver: str | None = None
    reason: str | None = None
    decided: int | None = None

    def public(self) -> dict[str, Any]:
        return asdict(self)


class ApprovalStore:
    """Approval requests from anysoar, decided by people in the console.

    Keeps the most recent ``history`` requests; pending ones are never dropped.
    """

    def __init__(self, bus: EventBus, history: int = 200) -> None:
        self._bus = bus
        self._history = history
        self._requests: OrderedDict[str, ApprovalRequest] = OrderedDict()
        self._settled: dict[str, asyncio.Event] = {}

    def submit(self, action: dict[str, Any], actor: str | None) -> ApprovalRequest:
        request = ApprovalRequest(action=action, actor=actor)
        self._requests[request.id] = request
        self._settled[request.id] = asyncio.Event()
        self._trim()
        self._bus.publish("approval", request.public())
        return request

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)

    def all(self) -> list[ApprovalRequest]:
        return list(self._requests.values())

    async def wait(self, approval_id: str, timeout: float) -> ApprovalRequest | None:
        """The request once it is settled, or as it is after ``timeout`` seconds."""
        settled = self._settled.get(approval_id)
        if settled is not None:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(timeout):
                    await settled.wait()
        return self.get(approval_id)

    def decide(
        self, approval_id: str, *, approved: bool, approver: str, reason: str | None
    ) -> ApprovalRequest:
        """Record a person's decision. Raises ``LookupError`` or ``ValueError``."""
        request = self._requests.get(approval_id)
        if request is None:
            raise LookupError(approval_id)
        if request.status != "pending":
            raise ValueError(f"approval is already {request.status}")
        request.status = "approved" if approved else "rejected"
        request.approver = approver
        request.reason = reason or None
        self._settle(request)
        return request

    def expire(self, approval_id: str) -> ApprovalRequest | None:
        request = self._requests.get(approval_id)
        if request is not None and request.status == "pending":
            request.status = "expired"
            self._settle(request)
        return request

    def _settle(self, request: ApprovalRequest) -> None:
        request.decided = _now()
        self._settled[request.id].set()
        self._bus.publish("approval", request.public())

    def _trim(self) -> None:
        settled = [k for k, r in self._requests.items() if r.status != "pending"]
        for key in settled[: max(0, len(self._requests) - self._history)]:
            del self._requests[key]
            self._settled.pop(key, None)
