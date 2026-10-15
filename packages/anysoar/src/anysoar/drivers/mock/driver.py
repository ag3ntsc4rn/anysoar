"""The mock driver: an in-memory fake SOAR implementing every capability."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from pydantic import JsonValue

from anysoar import __version__
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import (
    AlertQuery,
    Driver,
    DriverInfo,
    IndicatorEnrichment,
    Page,
    Playbook,
    PlaybookRun,
    PlaybookRunStatus,
)
from anysoar.models import (
    ActivityId,
    DetectionFinding,
    DetectionFindingStatusId,
    Enrichment,
    IncidentFinding,
    IncidentFindingStatusId,
    Note,
    Observable,
    Reputation,
    ReputationScoreId,
    SeverityId,
    Timestamp,
    VerdictId,
    now_timestamp,
)

from . import seed

__all__ = ["MockDriver"]

PROVIDER = "mock-intel"
"""Provider name on the mock driver's reputations and enrichments."""

_NEXT_STATUS = {
    PlaybookRunStatus.QUEUED: PlaybookRunStatus.RUNNING,
    PlaybookRunStatus.RUNNING: PlaybookRunStatus.SUCCEEDED,
}


@dataclass
class _Run:
    run: PlaybookRun
    playbook: Playbook
    case_uid: str | None
    error: str | None
    """Set when the run will fail once it leaves ``RUNNING``."""
    inputs: dict[str, JsonValue] = field(default_factory=dict)


class MockDriver(Driver):
    """An in-memory fake SOAR seeded with a synthetic phishing scenario.

    Every instance starts from the same seed (see :mod:`anysoar.drivers.mock.seed`) and keeps
    its own state, so changes made through one instance never leak into another.

    Behaviour is deterministic:

    - Enrichment of an indicator in the scenario returns a curated reputation; any other
      indicator gets ``UNKNOWN``. Enrichment data also lists the alerts and cases the indicator
      appears in.
    - A playbook run starts ``QUEUED`` and advances one step each time it is fetched with
      :meth:`get_playbook_run`: ``QUEUED`` → ``RUNNING`` → ``SUCCEEDED``. A run missing a required
      input ends ``FAILED`` instead. A finished run in the context of a case adds a note to it.
    - New uids are sequential (``note-0001``, ``run-0001``) and times come from ``clock``.

    Args:
        clock: Returns the current time as an OCSF timestamp. Pass a fixed clock for
            reproducible output.
    """

    name = "mock"

    def __init__(self, *, clock: Callable[[], Timestamp] = now_timestamp) -> None:
        self._clock = clock
        alerts = seed.build_alerts()
        self._alerts = {a.finding_info.uid: a for a in alerts}
        self._cases = {_case_uid(c): c for c in seed.build_cases(alerts)}
        self._playbooks = {p.uid: p for p in seed.build_playbooks()}
        self._reputations = seed.known_indicators()
        self._runs: dict[str, _Run] = {}
        self._counters: dict[str, int] = {}

    async def describe(self) -> DriverInfo:
        return DriverInfo(
            name=self.name,
            capabilities=self.implemented_capabilities(),
            driver_version=__version__,
            soar_product=seed.PRODUCT.name,
            soar_version=__version__,
        )

    # -- Alerts ---------------------------------------------------------------------------

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        query = query or AlertQuery()
        matches = [a for a in self._alerts.values() if _matches(a, query)]
        matches.sort(key=lambda a: (_created(a), a.finding_info.uid), reverse=True)
        start = _parse_cursor(query.cursor)
        end = start + query.limit
        return Page(
            items=[a.model_copy(deep=True) for a in matches[start:end]],
            next_cursor=str(end) if end < len(matches) else None,
        )

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        return self._alert(alert_uid).model_copy(deep=True)

    # -- Cases ----------------------------------------------------------------------------

    async def get_case(self, case_uid: str) -> IncidentFinding:
        return self._case(case_uid).model_copy(deep=True)

    async def add_note(self, case_uid: str, note: Note) -> Note:
        case = self._case(case_uid)
        now = self._clock()
        stored = note.model_copy(deep=True)
        if stored.uid is None:
            stored.uid = self._next_uid("note")
        if stored.created_time is None:
            stored.created_time = now
        case.notes = [*case.notes, stored]
        case.activity_id = ActivityId.UPDATE
        case.time = now
        return stored.model_copy(deep=True)

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        case = self._case(case_uid)
        now = self._clock()
        case.status_id = IncidentFindingStatusId.CLOSED
        case.verdict_id = verdict_id
        case.activity_id = ActivityId.CLOSE
        case.time = now
        case.end_time = now
        if comment is not None:
            case.comment = comment
        # Closing a case resolves the alerts it groups, as most SOARs do.
        for info in case.finding_info_list:
            alert = self._alerts.get(info.uid)
            if alert is not None:
                alert.status_id = DetectionFindingStatusId.RESOLVED
                alert.verdict_id = verdict_id
                alert.activity_id = ActivityId.UPDATE
                alert.time = max(alert.time, now)
        return case.model_copy(deep=True)

    # -- Indicators -----------------------------------------------------------------------

    async def enrich_indicator(self, indicator: Observable) -> IndicatorEnrichment:
        known = None
        if indicator.value is not None:
            known = self._reputations.get((indicator.type_id, indicator.value))
        score_id = known.score_id if known else ReputationScoreId.UNKNOWN
        observable = indicator.model_copy(deep=True)
        observable.reputation = Reputation(
            base_score=float(score_id * 10) if score_id != ReputationScoreId.UNKNOWN else 0.0,
            score_id=score_id,
            provider=PROVIDER,
        )
        if indicator.value is None:
            return IndicatorEnrichment(observable=observable)
        data: dict[str, JsonValue] = {
            "verdict": score_id.name.lower(),
            "tags": list(known.tags) if known else [],
            "related_alerts": _related(self._alerts, indicator),
            "related_cases": _related(self._cases, indicator),
        }
        enrichment = Enrichment(
            name=indicator.name or indicator.type_id.name.lower(),
            value=indicator.value,
            data=data,
            provider=PROVIDER,
            type="reputation",
        )
        return IndicatorEnrichment(observable=observable, enrichments=[enrichment])

    # -- Playbooks ------------------------------------------------------------------------

    async def list_playbooks(self) -> list[Playbook]:
        return list(self._playbooks.values())

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        playbook = self._playbooks.get(playbook_uid)
        if playbook is None:
            raise NotFoundError("playbook", playbook_uid)
        if case_uid is not None:
            self._case(case_uid)
        if alert_uid is not None:
            self._alert(alert_uid)
        inputs = dict(inputs or {})
        missing = [name for name in _required_inputs(playbook) if name not in inputs]
        run = PlaybookRun(
            uid=self._next_uid("run"),
            playbook_uid=playbook_uid,
            status=PlaybookRunStatus.QUEUED,
        )
        self._runs[run.uid] = _Run(
            run=run,
            playbook=playbook,
            case_uid=case_uid,
            error=f"missing required inputs: {', '.join(missing)}" if missing else None,
            inputs=inputs,
        )
        return run

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        state = self._runs.get(run_uid)
        if state is None:
            raise NotFoundError("playbook run", run_uid)
        if not state.run.status.is_finished:
            self._advance(state)
        return state.run

    def _advance(self, state: _Run) -> None:
        now = self._clock()
        status = _NEXT_STATUS[state.run.status]
        if status is PlaybookRunStatus.RUNNING:
            state.run = state.run.model_copy(update={"status": status, "started_time": now})
            return
        if state.error is not None:
            status, message, outputs = PlaybookRunStatus.FAILED, state.error, {}
        else:
            message = f"{state.playbook.name} completed."
            outputs = {"inputs": state.inputs}
        state.run = state.run.model_copy(
            update={"status": status, "ended_time": now, "message": message, "outputs": outputs}
        )
        if state.case_uid is not None:
            outcome = "succeeded" if status is PlaybookRunStatus.SUCCEEDED else "failed"
            text = f"Playbook {state.playbook.name!r} ({state.run.uid}) {outcome}: {message}"
            case = self._cases[state.case_uid]
            case.notes = [
                *case.notes,
                Note(
                    uid=self._next_uid("note"), comment=text, title="Playbook run", created_time=now
                ),
            ]

    # -- Helpers --------------------------------------------------------------------------

    def _alert(self, alert_uid: str) -> DetectionFinding:
        try:
            return self._alerts[alert_uid]
        except KeyError:
            raise NotFoundError("alert", alert_uid) from None

    def _case(self, case_uid: str) -> IncidentFinding:
        try:
            return self._cases[case_uid]
        except KeyError:
            raise NotFoundError("case", case_uid) from None

    def _next_uid(self, prefix: str) -> str:
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        return f"{prefix}-{self._counters[prefix]:04d}"


def _case_uid(case: IncidentFinding) -> str:
    if case.metadata.uid is None:
        raise ValueError("seeded cases must set metadata.uid")
    return case.metadata.uid


def _matches(alert: DetectionFinding, query: AlertQuery) -> bool:
    if query.status_ids is not None and alert.status_id not in query.status_ids:
        return False
    if query.min_severity_id is not None and (
        alert.severity_id == SeverityId.OTHER or alert.severity_id < query.min_severity_id
    ):
        return False
    created = _created(alert)
    if query.since is not None and created < query.since:
        return False
    return query.until is None or created < query.until


def _created(alert: DetectionFinding) -> int:
    """When the alert was created; ``time`` moves when the alert is updated."""
    created = alert.finding_info.created_time
    return created if created is not None else alert.time


def _parse_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    if not cursor.isdigit():
        raise DriverError(f"invalid cursor {cursor!r}")
    return int(cursor)


def _related(
    findings: Mapping[str, DetectionFinding] | Mapping[str, IncidentFinding], indicator: Observable
) -> list[JsonValue]:
    """Uids of the findings that include ``indicator`` among their observables, sorted."""
    uids: list[JsonValue] = []
    for uid in sorted(findings):
        if any(
            o.type_id == indicator.type_id and o.value == indicator.value
            for o in findings[uid].observables
        ):
            uids.append(uid)
    return uids


def _required_inputs(playbook: Playbook) -> list[str]:
    required = (playbook.input_schema or {}).get("required")
    return [r for r in required if isinstance(r, str)] if isinstance(required, list) else []
