"""What an agent is trying to do (:class:`Action`) and whether it may (:class:`Policy`)."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from anysoar.interface import ActionTier, Capability

__all__ = ["DEFAULT_TIER_DECISIONS", "Action", "Decision", "Policy"]


class Decision(StrEnum):
    """What the policy layer does with an action."""

    ALLOW = "allow"
    """Run it."""
    REQUIRE_APPROVAL = "require_approval"
    """Ask a human first; run it only if approved."""
    DENY = "deny"
    """Never run it."""


DEFAULT_TIER_DECISIONS = {
    ActionTier.READ: Decision.ALLOW,
    ActionTier.WRITE: Decision.REQUIRE_APPROVAL,
    ActionTier.DESTRUCTIVE: Decision.DENY,
}
"""Reads run freely, writes need approval, destructive actions are blocked."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Action(_Model):
    """One requested driver operation, as the policy layer, approvers and audit log see it."""

    capability: Capability
    tier: ActionTier
    """Risk of this call; for ``run_playbook``, the playbook's tier."""
    summary: str
    """One line a human can approve or reject, e.g. ``Close case case-0001 as benign``."""
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    """The operation's arguments as JSON."""

    @property
    def playbook_uid(self) -> str | None:
        uid = self.arguments.get("playbook_uid")
        return uid if isinstance(uid, str) else None


class Policy(_Model):
    """Maps actions to decisions.

    The decision for an action is, from most to least specific: its playbook's entry in
    ``playbooks`` (``run_playbook`` only), its capability's entry in ``capabilities``, then
    its tier's entry in ``tiers``.

    ``capabilities`` cannot contain ``run_playbook``: one setting for every playbook would
    also cover destructive ones. Set ``playbooks`` per playbook instead.
    """

    tiers: dict[ActionTier, Decision] = Field(default_factory=lambda: dict(DEFAULT_TIER_DECISIONS))
    capabilities: dict[Capability, Decision] = Field(default_factory=dict)
    playbooks: dict[str, Decision] = Field(default_factory=dict)
    """Decisions for individual playbooks, keyed by playbook uid."""

    @model_validator(mode="after")
    def _check(self) -> Self:
        missing = set(ActionTier) - set(self.tiers)
        if missing:
            raise ValueError(f"tiers must set a decision for: {', '.join(sorted(missing))}")
        if Capability.RUN_PLAYBOOK in self.capabilities:
            raise ValueError("set run_playbook decisions per playbook in 'playbooks'")
        return self

    def decide(self, action: Action) -> Decision:
        """The decision for ``action``."""
        uid = action.playbook_uid
        if action.capability is Capability.RUN_PLAYBOOK and uid in self.playbooks:
            return self.playbooks[uid]
        return self.capabilities.get(action.capability, self.tiers[action.tier])

    def decide_capability(self, capability: Capability) -> Decision:
        """The decision for any call of ``capability`` that has no playbook-specific entry."""
        return self.capabilities.get(capability, self.tiers[capability.tier])
