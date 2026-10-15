"""The policy layer between agents and drivers.

Every operation an agent requests becomes an :class:`Action` with a tier. A :class:`Policy`
decides whether it runs (``ALLOW``), needs a human's approval first (``REQUIRE_APPROVAL``) or
is refused (``DENY``). By default reads run freely, writes need approval and destructive
actions are blocked. :class:`GuardedDriver` applies this to any driver::

    from anysoar.drivers.mock import MockDriver
    from anysoar.policy import GuardedDriver, JsonlAuditLog

    soar = GuardedDriver(MockDriver(), approver=my_approver, audit_log=JsonlAuditLog(path))

Every step of every call is recorded in the audit log (see :mod:`anysoar.policy.audit`), and
a :class:`KillSwitch` stops all operations at once.
"""

from anysoar.policy.approval import Approval, ApprovalUnavailableError, ApproveAll, Approver
from anysoar.policy.audit import (
    AuditEvent,
    AuditEventKind,
    AuditLog,
    JsonlAuditLog,
    MemoryAuditLog,
    audit_actor,
)
from anysoar.policy.guard import GuardedDriver
from anysoar.policy.kill_switch import KillSwitch
from anysoar.policy.rules import DEFAULT_TIER_DECISIONS, Action, Decision, Policy

__all__ = [
    "DEFAULT_TIER_DECISIONS",
    "Action",
    "Approval",
    "ApprovalUnavailableError",
    "ApproveAll",
    "Approver",
    "AuditEvent",
    "AuditEventKind",
    "AuditLog",
    "Decision",
    "GuardedDriver",
    "JsonlAuditLog",
    "KillSwitch",
    "MemoryAuditLog",
    "Policy",
    "audit_actor",
]
