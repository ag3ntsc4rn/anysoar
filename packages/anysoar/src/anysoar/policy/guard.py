"""The guarded driver: applies a :class:`~anysoar.policy.Policy` to every driver operation."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

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
    CaseQuery,
    Driver,
    DriverInfo,
    IndicatorEnrichment,
    Page,
    Playbook,
    PlaybookRun,
)
from anysoar.models import DetectionFinding, IncidentFinding, Note, Observable, VerdictId
from anysoar.policy.approval import Approval, ApprovalUnavailableError, Approver
from anysoar.policy.audit import AuditEvent, AuditEventKind, AuditLog
from anysoar.policy.kill_switch import KillSwitch
from anysoar.policy.rules import Action, Decision, Policy

__all__ = ["GuardedDriver"]

logger = logging.getLogger(__name__)

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
        audit_log: Receives an :class:`~anysoar.policy.AuditEvent` for every step of every
            call. If an action cannot be recorded before it runs, it is denied. Closing the
            guard closes the log.
        kill_switch: While engaged, every operation is denied. Checked when a call arrives
            and again after approval.
    """

    name = "guarded"

    def __init__(
        self,
        driver: Driver,
        *,
        policy: Policy | None = None,
        approver: Approver | None = None,
        approval_timeout: float | None = 300.0,
        audit_log: AuditLog | None = None,
        kill_switch: KillSwitch | None = None,
    ) -> None:
        self.driver = driver
        self.audit_log = audit_log
        self.kill_switch = kill_switch
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
        try:
            await self.driver.aclose()
        finally:
            if self.audit_log is not None:
                await self.audit_log.aclose()

    async def action(self, capability: Capability, /, **arguments: Any) -> Action:
        """The :class:`Action` a call would produce, without running or recording it.

        ``arguments`` are the keyword arguments of the corresponding :class:`Driver` method.
        Lets a caller (e.g. the MCP server) show a human exactly what will be judged, and ask
        the policy about it, before making the call. For ``run_playbook`` this looks up the
        playbook, so it can raise :class:`~anysoar.errors.NotFoundError`.
        """
        if capability is Capability.RUN_PLAYBOOK:
            return await self._run_playbook_action(**arguments)
        return _ACTION_BUILDERS[capability](**arguments)

    # -- Alerts ---------------------------------------------------------------------------

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        return await self._guarded(
            _list_alerts_action(query), lambda: self.driver.list_alerts(query)
        )

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        return await self._guarded(
            _get_alert_action(alert_uid), lambda: self.driver.get_alert(alert_uid)
        )

    # -- Cases ----------------------------------------------------------------------------

    async def list_cases(self, query: CaseQuery | None = None) -> Page[IncidentFinding]:
        return await self._guarded(_list_cases_action(query), lambda: self.driver.list_cases(query))

    async def get_case(self, case_uid: str) -> IncidentFinding:
        return await self._guarded(
            _get_case_action(case_uid), lambda: self.driver.get_case(case_uid)
        )

    async def add_note(self, case_uid: str, note: Note) -> Note:
        return await self._guarded(
            _add_note_action(case_uid, note),
            lambda: self.driver.add_note(case_uid, note),
            lambda n: n.uid,
        )

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        return await self._guarded(
            _close_case_action(case_uid, verdict_id=verdict_id, comment=comment),
            lambda: self.driver.close_case(case_uid, verdict_id=verdict_id, comment=comment),
            lambda _: case_uid,
        )

    # -- Indicators -----------------------------------------------------------------------

    async def enrich_indicator(self, indicator: Observable) -> IndicatorEnrichment:
        return await self._guarded(
            _enrich_indicator_action(indicator), lambda: self.driver.enrich_indicator(indicator)
        )

    # -- Playbooks ------------------------------------------------------------------------

    async def list_playbooks(self) -> list[Playbook]:
        return await self._guarded(_list_playbooks_action(), self.driver.list_playbooks)

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        action = await self._run_playbook_action(
            playbook_uid, case_uid=case_uid, alert_uid=alert_uid, inputs=inputs
        )
        return await self._guarded(
            action,
            lambda: self.driver.run_playbook(
                playbook_uid, case_uid=case_uid, alert_uid=alert_uid, inputs=inputs
            ),
            lambda run: run.uid,
        )

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        return await self._guarded(
            _get_playbook_run_action(run_uid), lambda: self.driver.get_playbook_run(run_uid)
        )

    # -- Policy ---------------------------------------------------------------------------

    async def _run_playbook_action(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> Action:
        self._require_supported(Capability.RUN_PLAYBOOK)
        playbook = await self._find_playbook(playbook_uid)
        name = f"{playbook.name!r} ({playbook_uid})" if playbook else playbook_uid
        targets = [
            f"{kind} {uid}" for kind, uid in (("case", case_uid), ("alert", alert_uid)) if uid
        ]
        return Action(
            capability=Capability.RUN_PLAYBOOK,
            tier=playbook.tier if playbook else ActionTier.DESTRUCTIVE,
            summary=_clip(
                f"Run playbook {name}" + (" on " + " and ".join(targets) if targets else "")
            ),
            arguments={
                "playbook_uid": playbook_uid,
                "case_uid": case_uid,
                "alert_uid": alert_uid,
                "inputs": dict(inputs or {}),
            },
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

    async def _guarded[T](
        self,
        action: Action,
        call: Callable[[], Awaitable[T]],
        result_ref: Callable[[T], str | None] | None = None,
    ) -> T:
        self._require_supported(action.capability)
        decision = self.policy.decide(action)
        call_uid = uuid.uuid4().hex

        def event(kind: AuditEventKind, **fields: object) -> AuditEvent:
            return AuditEvent.for_action(
                action, call_uid=call_uid, driver=self.driver.name, kind=kind, **fields
            )

        try:
            await self._record(
                event(AuditEventKind.REQUESTED, decision=decision, arguments=action.arguments)
            )
        except Exception as exc:
            raise PolicyDeniedError(
                action.capability,
                DenialReason.AUDIT_UNAVAILABLE,
                f"could not write the audit log: {exc}",
            ) from exc
        try:
            self._check_kill_switch(action)
            if decision is Decision.DENY:
                raise PolicyDeniedError(
                    action.capability,
                    DenialReason.POLICY,
                    f"{action.tier.value} action denied by policy",
                )
            if decision is Decision.REQUIRE_APPROVAL:
                await self._approve(
                    action, lambda a: self._record(event(AuditEventKind.APPROVAL, approval=a))
                )
                self._check_kill_switch(action)
        except PolicyDeniedError as denied:
            await self._record_quietly(
                event(AuditEventKind.DENIED, reason=denied.reason, detail=denied.detail)
            )
            raise

        started = time.monotonic()
        try:
            result = await call()
        except Exception as exc:
            await self._record_quietly(
                event(
                    AuditEventKind.FAILED,
                    error_type=type(exc).__name__,
                    detail=str(exc),
                    duration_ms=_elapsed_ms(started),
                )
            )
            raise
        await self._record_quietly(
            event(
                AuditEventKind.COMPLETED,
                result_ref=result_ref(result) if result_ref else None,
                duration_ms=_elapsed_ms(started),
            )
        )
        return result

    async def _approve(
        self, action: Action, on_answer: Callable[[Approval], Awaitable[None]]
    ) -> None:
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
        try:
            await on_answer(approval)
        except Exception as exc:
            raise PolicyDeniedError(
                capability,
                DenialReason.AUDIT_UNAVAILABLE,
                f"could not write the audit log: {exc}",
            ) from exc
        if not approval.approved:
            who = f" by {approval.approver}" if approval.approver else ""
            detail = f"rejected{who}" + (f": {approval.reason}" if approval.reason else "")
            raise PolicyDeniedError(capability, DenialReason.APPROVAL_REJECTED, detail)

    def _check_kill_switch(self, action: Action) -> None:
        reason = self.kill_switch.reason if self.kill_switch is not None else None
        if reason is not None:
            raise PolicyDeniedError(action.capability, DenialReason.KILL_SWITCH, reason)

    async def _record(self, event: AuditEvent) -> None:
        if self.audit_log is not None:
            await self.audit_log.record(event)

    async def _record_quietly(self, event: AuditEvent) -> None:
        """Record an event that must not change the call's outcome if it cannot be written."""
        try:
            await self._record(event)
        except Exception:
            logger.exception(
                "could not write %s audit event for call %s", event.kind, event.call_uid
            )


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def _action(
    capability: Capability, summary: str, arguments: dict[str, JsonValue] | None = None
) -> Action:
    return Action(
        capability=capability,
        tier=capability.tier,
        summary=_clip(summary),
        arguments=arguments or {},
    )


def _list_alerts_action(query: AlertQuery | None = None) -> Action:
    arguments = (query or AlertQuery()).model_dump(mode="json", exclude_defaults=True)
    return _action(Capability.LIST_ALERTS, "List alerts", arguments)


def _get_alert_action(alert_uid: str) -> Action:
    return _action(Capability.GET_ALERT, f"Get alert {alert_uid}", {"alert_uid": alert_uid})


def _list_cases_action(query: CaseQuery | None = None) -> Action:
    arguments = (query or CaseQuery()).model_dump(mode="json", exclude_defaults=True)
    return _action(Capability.LIST_CASES, "List cases", arguments)


def _get_case_action(case_uid: str) -> Action:
    return _action(Capability.GET_CASE, f"Get case {case_uid}", {"case_uid": case_uid})


def _add_note_action(case_uid: str, note: Note) -> Action:
    return _action(
        Capability.ADD_NOTE,
        f"Add a note to case {case_uid}: {note.comment!r}",
        {"case_uid": case_uid, "note": note.to_ocsf()},
    )


def _close_case_action(
    case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
) -> Action:
    verdict = verdict_id.name.lower()
    summary = f"Close case {case_uid} as {verdict}" + (f": {comment!r}" if comment else "")
    return _action(
        Capability.CLOSE_CASE,
        summary,
        {"case_uid": case_uid, "verdict": verdict, "comment": comment},
    )


def _enrich_indicator_action(indicator: Observable) -> Action:
    return _action(
        Capability.ENRICH_INDICATOR,
        f"Enrich {indicator.type_id.name.lower()} {indicator.value}",
        {"indicator": indicator.to_ocsf()},
    )


def _list_playbooks_action() -> Action:
    return _action(Capability.LIST_PLAYBOOKS, "List playbooks")


def _get_playbook_run_action(run_uid: str) -> Action:
    return _action(Capability.GET_PLAYBOOK_RUN, f"Get playbook run {run_uid}", {"run_uid": run_uid})


_ACTION_BUILDERS: dict[Capability, Callable[..., Action]] = {
    Capability.LIST_ALERTS: _list_alerts_action,
    Capability.GET_ALERT: _get_alert_action,
    Capability.LIST_CASES: _list_cases_action,
    Capability.GET_CASE: _get_case_action,
    Capability.ADD_NOTE: _add_note_action,
    Capability.CLOSE_CASE: _close_case_action,
    Capability.ENRICH_INDICATOR: _enrich_indicator_action,
    Capability.LIST_PLAYBOOKS: _list_playbooks_action,
    Capability.GET_PLAYBOOK_RUN: _get_playbook_run_action,
}
