"""The audit log: an append-only record of every action the policy layer evaluates.

Each call produces events sharing a ``call_uid``: ``requested`` (with the policy decision and
arguments), ``approval`` when someone was asked, then exactly one of ``completed``,
``denied`` or ``failed``. Every event carries the action's capability, tier and summary, so
each line of a JSONL log stands on its own.
"""

from __future__ import annotations

import logging
import os
import uuid
from contextvars import ContextVar
from enum import StrEnum
from pathlib import Path
from typing import IO, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from anysoar.errors import DenialReason
from anysoar.interface import ActionTier, Capability
from anysoar.models import Timestamp, now_timestamp
from anysoar.policy.approval import Approval
from anysoar.policy.rules import Action, Decision

__all__ = [
    "AuditEvent",
    "AuditEventKind",
    "AuditLog",
    "JsonlAuditLog",
    "MemoryAuditLog",
    "audit_actor",
]

logger = logging.getLogger(__name__)

audit_actor: ContextVar[str | None] = ContextVar("anysoar_audit_actor", default=None)
"""Who is acting, recorded on audit events; set by the caller (e.g. the MCP server)."""


class AuditEventKind(StrEnum):
    REQUESTED = "requested"
    """An action was requested and the policy decided what to do with it."""
    APPROVAL = "approval"
    """An approver answered."""
    COMPLETED = "completed"
    """The driver call succeeded."""
    DENIED = "denied"
    """The policy layer refused the action; the SOAR was not called."""
    FAILED = "failed"
    """The driver call raised an error."""


class AuditEvent(BaseModel):
    """One audit log entry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uid: str = Field(default_factory=lambda: uuid.uuid4().hex)
    call_uid: str
    """Shared by all events of one call."""
    kind: AuditEventKind
    time: Timestamp = Field(default_factory=now_timestamp)
    actor: str | None = Field(default_factory=lambda: audit_actor.get())
    driver: str
    capability: Capability
    tier: ActionTier
    summary: str
    decision: Decision | None = None
    """Set on ``requested``."""
    arguments: dict[str, JsonValue] | None = None
    """Set on ``requested``."""
    approval: Approval | None = None
    """Set on ``approval``."""
    reason: DenialReason | None = None
    """Set on ``denied``."""
    detail: str | None = None
    """Why the action was denied or failed."""
    error_type: str | None = None
    """Set on ``failed``: the exception class name."""
    result_ref: str | None = None
    """Set on ``completed`` where useful: the uid of the note, case or run produced."""
    duration_ms: int | None = None
    """Set on ``completed`` and ``failed``: how long the driver call took."""

    @classmethod
    def for_action(
        cls, action: Action, *, call_uid: str, driver: str, kind: AuditEventKind, **fields: object
    ) -> AuditEvent:
        return cls.model_validate(
            {
                "call_uid": call_uid,
                "kind": kind,
                "driver": driver,
                "capability": action.capability,
                "tier": action.tier,
                "summary": action.summary,
                **fields,
            }
        )


class AuditLog(Protocol):
    """Where audit events go. ``record`` must raise if the event could not be stored."""

    async def record(self, event: AuditEvent) -> None: ...

    async def aclose(self) -> None: ...


class MemoryAuditLog:
    """Keeps events in a list. For tests, and for in-process consumers such as a console."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    async def aclose(self) -> None:
        pass


class JsonlAuditLog:
    """Appends events to a file, one JSON object per line, flushed as they are written.

    The file and its parent directory are created if needed, with permissions limited to the
    current user, since events contain SOAR data.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._file: IO[str] | None = None

    async def record(self, event: AuditEvent) -> None:
        file = self._open()
        file.write(event.model_dump_json(exclude_none=True) + "\n")
        file.flush()

    async def aclose(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def _open(self) -> IO[str]:
        if self._file is None:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            self._file = os.fdopen(fd, "a", encoding="utf-8")
        return self._file
