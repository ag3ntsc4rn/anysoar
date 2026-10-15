"""Approvals: how the policy layer asks a human before running a write action."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

from anysoar.errors import AnysoarError
from anysoar.policy.rules import Action

__all__ = ["Approval", "ApprovalUnavailableError", "ApproveAll", "Approver"]


class Approval(BaseModel):
    """An approver's decision on one action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approved: bool
    approver: str | None = None
    """Who decided, e.g. a user name or ``"auto"``."""
    reason: str | None = None


class ApprovalUnavailableError(AnysoarError):
    """The approver has no way to ask anyone right now (e.g. the client cannot prompt)."""


class Approver(Protocol):
    """Asks for a decision on an action that the policy says needs approval.

    Implementations may wait for a human for as long as they like; the policy layer applies
    its own timeout. Raise :class:`ApprovalUnavailableError` if no one can be asked.
    """

    async def request_approval(self, action: Action) -> Approval: ...


class ApproveAll:
    """Approves everything. For tests and local experiments only, never with a real SOAR."""

    async def request_approval(self, action: Action) -> Approval:
        return Approval(approved=True, approver="auto", reason="ApproveAll approver")
