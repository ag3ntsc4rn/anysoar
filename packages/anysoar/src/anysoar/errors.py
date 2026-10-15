"""Exceptions raised by anysoar and its drivers."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from anysoar.interface import Capability

__all__ = [
    "AnysoarError",
    "CapabilityNotSupportedError",
    "DenialReason",
    "DriverError",
    "NotFoundError",
    "PolicyDeniedError",
]


class AnysoarError(Exception):
    """Base class for all anysoar errors."""


class CapabilityNotSupportedError(AnysoarError):
    """The driver, or the SOAR behind it, does not support the requested operation."""

    def __init__(self, capability: Capability, driver: str | None = None) -> None:
        self.capability = capability
        self.driver = driver
        where = f" by driver {driver!r}" if driver else ""
        super().__init__(f"{capability.value} is not supported{where}")


class NotFoundError(AnysoarError):
    """The requested alert, case, playbook or run does not exist in the SOAR."""

    def __init__(self, kind: str, uid: str) -> None:
        self.kind = kind
        self.uid = uid
        super().__init__(f"{kind} {uid!r} not found")


class DriverError(AnysoarError):
    """The SOAR returned an error or could not be reached.

    ``retryable`` is a hint that the same call may succeed later (timeouts, rate limits).
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        self.retryable = retryable
        super().__init__(message)


class DenialReason(StrEnum):
    """Why the policy layer refused an operation."""

    POLICY = "policy"
    """The policy denies this operation outright."""
    APPROVAL_REJECTED = "approval_rejected"
    """A human (or the configured approver) rejected the operation."""
    APPROVAL_TIMEOUT = "approval_timeout"
    """No approval decision arrived in time."""
    APPROVAL_UNAVAILABLE = "approval_unavailable"
    """The operation needs approval but there is no way to ask for it."""
    KILL_SWITCH = "kill_switch"
    """The kill switch is engaged; no operations run."""


class PolicyDeniedError(AnysoarError):
    """The policy layer refused to run an operation. The SOAR was not called."""

    def __init__(self, capability: Capability, reason: DenialReason, detail: str) -> None:
        self.capability = capability
        self.reason = reason
        self.detail = detail
        super().__init__(f"{capability.value} denied ({reason.value}): {detail}")
