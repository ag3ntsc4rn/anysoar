"""The guarded driver: applies a :class:`~anysoar.policy.Policy` to every driver operation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping

from pydantic import JsonValue

from anysoar.errors import (
    CapabilityNotSupportedError,
    DenialReason,
    NotFoundError,
    PolicyDeniedError,
)
from anysoar.interface import (
    ActionTier,
    AlertQuery,
    Capability,
    Driver,
    DriverInfo,
    IndicatorEnrichment,
    Page,
    Playbook,
    PlaybookRun,
)
from anysoar.models import DetectionFinding, IncidentFinding, Note, Observable, VerdictId
from anysoar.policy.approval import ApprovalUnavailableError, Approver
from anysoar.policy.rules import Action, Decision, Policy

__all__ = ["GuardedDriver"]

_SUMMARY_LIMIT = 200


def _clip(text: str) -> str:
    return text if len(text) <= _SUMMARY_LIMIT else text[: _SUMMARY_LIMIT - 1] + "…"


class GuardedDriver(Driver):
    """Wraps a driver so that every operation goes through the policy layer.

    For each call it builds an :class:`~anysoar.policy.Action`, asks the policy for a
    decision, asks the approver when approval is required, and only then calls the wrapped
    driver. Refusals raise :class:`~anysoar.errors.PolicyDeniedError` without touching the
    SOAR.

    ``run_playbook`` is judged by the playbook's own tier. If the wrapped driver cannot list
    playbooks, their risk is unknown and they are treated as destructive.

    :meth:`describe` reports the wrapped driver's capabilities minus those the policy always
    denies. With an approver that approves everything, a guarded driver behaves exactly like
    the driver it wraps.

    Args:
        driver: The driver to guard. Closing the guard closes it.
        policy: Defaults to :class:`~anysoar.policy.Policy` (reads allowed, writes need
            approval, destructive actions denied).
        approver: Asked when an action needs approval. Without one, such actions are
            denied.
        approval_timeout: Seconds to wait for an approval before denying; ``None`` waits
            forever.
    """

    name = "guarded"

    def __init__(
        self,
        driver: Driver,
        *,
        policy: Policy | None = None,
        approver: Approver | None = None,
        approval_timeout: float | None = 300.0,
    ) -> None:
        self.driver = driver
        self.policy = policy or Policy()
        self.approver = approver
        self.approval_timeout = approval_timeout
        # A guard reports the name of the driver it wraps.
        self.name = driver.name  # type: ignore[misc]

    async def describe(self) -> DriverInfo:
        info = await self.driver.describe()
        allowed = frozenset(
            c
            for c in info.capabilities
            if c is Capability.RUN_PLAYBOOK or self.policy.decide_capability(c) is not Decision.DENY
        )
        return info.model_copy(update={"capabilities": allowed})

    async def aclose(self) -> None:
        await self.driver.aclose()

    # -- Alerts ---------------------------------------------------------------------------

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        arguments = (query or AlertQuery()).model_dump(mode="json", exclude_defaults=True)
        action = self._action(Capability.LIST_ALERTS, "List alerts", arguments)
        return await self._guarded(action, lambda: self.driver.list_alerts(query))

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        action = self._action(
            Capability.GET_ALERT, f"Get alert {alert_uid}", {"alert_uid": alert_uid}
        )
        return await self._guarded(action, lambda: self.driver.get_alert(alert_uid))

    # -- Cases ----------------------------------------------------------------------------

    async def get_case(self, case_uid: str) -> IncidentFinding:
        action = self._action(Capability.GET_CASE, f"Get case {case_uid}", {"case_uid": case_uid})
        return await self._guarded(action, lambda: self.driver.get_case(case_uid))

    async def add_note(self, case_uid: str, note: Note) -> Note:
        action = self._action(
            Capability.ADD_NOTE,
            f"Add a note to case {case_uid}: {note.comment!r}",
            {"case_uid": case_uid, "note": note.to_ocsf()},
        )
        return await self._guarded(action, lambda: self.driver.add_note(case_uid, note))

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        verdict = verdict_id.name.lower()
        summary = f"Close case {case_uid} as {verdict}" + (f": {comment!r}" if comment else "")
        action = self._action(
            Capability.CLOSE_CASE,
            summary,
            {"case_uid": case_uid, "verdict": verdict, "comment": comment},
        )
        return await self._guarded(
            action,
            lambda: self.driver.close_case(case_uid, verdict_id=verdict_id, comment=comment),
        )

    # -- Indicators -----------------------------------------------------------------------

    async def enrich_indicator(self, indicator: Observable) -> IndicatorEnrichment:
        action = self._action(
            Capability.ENRICH_INDICATOR,
            f"Enrich {indicator.type_id.name.lower()} {indicator.value}",
            {"indicator": indicator.to_ocsf()},
        )
        return await self._guarded(action, lambda: self.driver.enrich_indicator(indicator))

    # -- Playbooks ------------------------------------------------------------------------

    async def list_playbooks(self) -> list[Playbook]:
        action = self._action(Capability.LIST_PLAYBOOKS, "List playbooks")
        return await self._guarded(action, self.driver.list_playbooks)

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        self._require_supported(Capability.RUN_PLAYBOOK)
        playbook = await self._find_playbook(playbook_uid)
        name = f"{playbook.name!r} ({playbook_uid})" if playbook else playbook_uid
        target = " on " + " and ".join(
            f"{kind} {uid}" for kind, uid in (("case", case_uid), ("alert", alert_uid)) if uid
        )
        action = Action(
            capability=Capability.RUN_PLAYBOOK,
            tier=playbook.tier if playbook else ActionTier.DESTRUCTIVE,
            summary=_clip(f"Run playbook {name}" + (target if case_uid or alert_uid else "")),
            arguments={
                "playbook_uid": playbook_uid,
                "case_uid": case_uid,
                "alert_uid": alert_uid,
                "inputs": dict(inputs or {}),
            },
        )
        return await self._guarded(
            action,
            lambda: self.driver.run_playbook(
                playbook_uid, case_uid=case_uid, alert_uid=alert_uid, inputs=inputs
            ),
        )

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        action = self._action(
            Capability.GET_PLAYBOOK_RUN, f"Get playbook run {run_uid}", {"run_uid": run_uid}
        )
        return await self._guarded(action, lambda: self.driver.get_playbook_run(run_uid))

    # -- Policy ---------------------------------------------------------------------------

    def _action(
        self, capability: Capability, summary: str, arguments: dict[str, JsonValue] | None = None
    ) -> Action:
        return Action(
            capability=capability,
            tier=capability.tier,
            summary=_clip(summary),
            arguments=arguments or {},
        )

    def _require_supported(self, capability: Capability) -> None:
        if capability not in type(self.driver).implemented_capabilities():
            raise CapabilityNotSupportedError(capability, driver=self.driver.name)

    async def _find_playbook(self, playbook_uid: str) -> Playbook | None:
        """The playbook, or ``None`` if the driver cannot list playbooks."""
        if Capability.LIST_PLAYBOOKS not in type(self.driver).implemented_capabilities():
            return None
        for playbook in await self.driver.list_playbooks():
            if playbook.uid == playbook_uid:
                return playbook
        raise NotFoundError("playbook", playbook_uid)

    async def _guarded[T](self, action: Action, call: Callable[[], Awaitable[T]]) -> T:
        self._require_supported(action.capability)
        decision = self.policy.decide(action)
        if decision is Decision.DENY:
            raise PolicyDeniedError(
                action.capability,
                DenialReason.POLICY,
                f"{action.tier.value} action denied by policy",
            )
        if decision is Decision.REQUIRE_APPROVAL:
            await self._approve(action)
        return await call()

    async def _approve(self, action: Action) -> None:
        capability = action.capability
        if self.approver is None:
            raise PolicyDeniedError(
                capability, DenialReason.APPROVAL_UNAVAILABLE, "needs approval; no approver set"
            )
        try:
            async with asyncio.timeout(self.approval_timeout):
                approval = await self.approver.request_approval(action)
        except TimeoutError:
            raise PolicyDeniedError(
                capability,
                DenialReason.APPROVAL_TIMEOUT,
                f"no approval decision within {self.approval_timeout:g}s",
            ) from None
        except ApprovalUnavailableError as exc:
            raise PolicyDeniedError(
                capability, DenialReason.APPROVAL_UNAVAILABLE, str(exc)
            ) from exc
        if not approval.approved:
            who = f" by {approval.approver}" if approval.approver else ""
            detail = f"rejected{who}" + (f": {approval.reason}" if approval.reason else "")
            raise PolicyDeniedError(capability, DenialReason.APPROVAL_REJECTED, detail)
