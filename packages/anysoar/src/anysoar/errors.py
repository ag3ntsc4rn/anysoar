"""Exceptions raised by anysoar and its drivers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from anysoar.interface import Capability

__all__ = ["AnysoarError", "CapabilityNotSupportedError", "DriverError", "NotFoundError"]


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
