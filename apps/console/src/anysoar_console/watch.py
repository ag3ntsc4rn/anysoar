"""Background watchers: the audit log as it grows, and the kill switch file."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from anysoar.drivers import SoarSwitch
from anysoar.policy import KillSwitch
from anysoar_console.store import EventBus, Feed

__all__ = ["follow_audit_log", "soar_state", "watch_kill_switch", "watch_soar_switch"]

_AUDIT_FIELDS = (
    "call_uid",
    "kind",
    "time",
    "actor",
    "driver",
    "capability",
    "tier",
    "summary",
    "decision",
    "reason",
    "detail",
    "error_type",
    "result_ref",
    "duration_ms",
)


def audit_entry(line: str) -> dict[str, Any] | None:
    """The fields of an audit event the console shows, or None for a line it cannot read."""
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if not isinstance(event, dict) or "kind" not in event:
        return None
    entry = {k: event[k] for k in _AUDIT_FIELDS if k in event}
    approval = event.get("approval")
    if isinstance(approval, dict):
        entry["approval"] = {k: approval.get(k) for k in ("approved", "approver", "reason")}
    return entry


async def follow_audit_log(
    path: Path, feed: Feed, *, interval: float = 0.5, backlog: int = 100
) -> None:
    """Add the last ``backlog`` events of the audit log to ``feed``, then each new one."""
    offset = 0
    pending = b""
    first = True
    while True:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        if size < offset:  # truncated or replaced
            offset, pending = 0, b""
        if size > offset:
            with path.open("rb") as file:
                file.seek(offset)
                chunk = file.read(size - offset)
            offset = size
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()  # an incomplete last line waits for the rest
            if first:
                lines = lines[-backlog:]
            for line in lines:
                entry = audit_entry(line.decode("utf-8", "replace"))
                if entry is not None:
                    feed.add(entry)
        first = False
        await asyncio.sleep(interval)


async def watch_kill_switch(switch: KillSwitch, bus: EventBus, *, interval: float = 1.0) -> None:
    """Publish ``kill_switch`` events whenever the switch is engaged or released."""
    last: str | None = None
    first = True
    while True:
        reason = switch.reason
        if first or reason != last:
            state = {"available": True, "engaged": reason is not None, "reason": reason}
            bus.publish("kill_switch", state)
            last, first = reason, False
        await asyncio.sleep(interval)


def soar_state(switch: SoarSwitch | None) -> dict[str, Any]:
    if switch is None:
        return {"available": False, "active": None, "choices": []}
    return {"available": True, "active": switch.active, "choices": switch.choices}


async def watch_soar_switch(switch: SoarSwitch, bus: EventBus, *, interval: float = 1.0) -> None:
    """Publish ``soar`` events whenever the active SOAR changes, wherever it was switched."""
    last: str | None = None
    while True:
        active = switch.active
        if active != last:
            bus.publish("soar", soar_state(switch))
            last = active
        await asyncio.sleep(interval)
