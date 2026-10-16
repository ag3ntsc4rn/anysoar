"""The anysoar MCP server: SOAR operations as MCP tools, behind the policy layer.

This module deliberately has no ``from __future__ import annotations``: the MCP SDK reads
tool and resolver annotations at registration time.
"""

import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from anysoar._extras import missing_extra

try:
    import mcp  # noqa: F401  (fail early with install advice if the extra is missing)
except ModuleNotFoundError as exc:
    raise missing_extra("mcp", exc) from exc

from mcp.server.mcpserver import (
    AcceptedElicitation,
    Context,
    Elicit,
    ElicitationResult,
    MCPServer,
    Resolve,
)
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, JsonValue

from anysoar import __version__
from anysoar.errors import (
    CapabilityNotSupportedError,
    DriverError,
    NotFoundError,
    PolicyDeniedError,
)
from anysoar.interface import ActionTier, AlertQuery, Capability, CaseQuery
from anysoar.models import (
    DetectionFindingStatusId,
    IncidentFindingStatusId,
    Note,
    Observable,
    ObservableTypeId,
    SeverityId,
    VerdictId,
    to_timestamp,
)
from anysoar.policy import (
    Action,
    Approval,
    ApprovalUnavailableError,
    Decision,
    GuardedDriver,
    audit_actor,
)

__all__ = ["ApprovalForm", "ElicitationApprover", "create_server"]

INSTRUCTIONS = """\
anysoar connects you to a SOAR platform through a policy layer. Call describe_soar first: it \
lists the operations available and whether each runs freely, needs approval or is denied.

- Read tools run freely. Write tools (such as add_note, close_case and run_playbook) need a \
human's approval: the user is asked to confirm in their MCP client. If they decline, the tool \
fails with "Denied by anysoar policy". Do not retry a declined action; explain and move on.
- Destructive playbooks are denied. list_playbooks shows each playbook's policy.
- If calls fail with reason "kill_switch", an operator has stopped all actions. Stop and tell \
the user.
- Alerts are OCSF 1.9.0 Detection Findings; an alert's id is finding_info.uid. Cases are OCSF \
Incident Findings; a case's id is metadata.uid. Indicators are OCSF observables.
"""

Verdict = Literal[
    "false_positive",
    "true_positive",
    "disregard",
    "suspicious",
    "benign",
    "test",
    "insufficient_data",
    "security_risk",
    "managed_externally",
    "duplicate",
]
AlertStatus = Literal["new", "in_progress", "suppressed", "resolved", "archived", "deleted"]
CaseStatus = Literal["new", "in_progress", "on_hold", "resolved", "closed"]
Severity = Literal["informational", "low", "medium", "high", "critical", "fatal"]
IndicatorType = Literal[
    "hostname",
    "ip_address",
    "mac_address",
    "user_name",
    "email_address",
    "url_string",
    "file_name",
    "hash",
    "process_name",
    "port",
    "subnet",
    "command_line",
    "http_user_agent",
    "fingerprint",
]


class ApprovalForm(BaseModel):
    """What the user is asked when an action needs approval."""

    approve: bool = Field(description="Allow the agent to perform this action?")
    reason: str = Field(default="", description="Optional note for the audit log.")


class _NotAsked(BaseModel):
    """Resolver outcome when no question was put to the user."""

    why: Literal["not_required", "unsupported", "error"]


_Answer = ElicitationResult[ApprovalForm]
_answer: ContextVar[Any] = ContextVar("anysoar_mcp_approval_answer", default=None)


class ElicitationApprover:
    """Approves with the answer the user gave in their MCP client for the current tool call.

    The MCP server asks the user (MCP elicitation) before a tool body runs, because on
    current protocol versions a server cannot prompt in the middle of a call. This approver
    hands that answer to the policy layer, which still decides, audits and checks the kill
    switch. Approval is only as trustworthy as the MCP client that shows the question.
    """

    async def request_approval(self, action: Action) -> Approval:
        answer = _answer.get()
        actor = audit_actor.get()
        if isinstance(answer, AcceptedElicitation) and isinstance(answer.data, ApprovalForm):
            form = answer.data
            return Approval(approved=form.approve, approver=actor, reason=form.reason or None)
        if isinstance(answer, AcceptedElicitation) and isinstance(answer.data, _NotAsked):
            if answer.data.why == "unsupported":
                raise ApprovalUnavailableError(
                    "the MCP client cannot ask the user for approval (no form elicitation)"
                )
            raise ApprovalUnavailableError("approval was not requested for this action")
        if answer is not None:
            outcome = {"decline": "declined", "cancel": "cancelled"}.get(answer.action, "rejected")
            return Approval(approved=False, approver=actor, reason=f"{outcome} in the MCP client")
        raise ApprovalUnavailableError("approval was not requested for this action")


async def create_server(guard: GuardedDriver, *, name: str = "anysoar") -> MCPServer:
    """Build an MCP server exposing ``guard``'s operations as tools.

    Only operations the guarded driver reports in ``describe()`` become tools, plus
    ``describe_soar``. If ``guard.approver`` is an :class:`ElicitationApprover`, the user is
    asked in their MCP client whenever the policy requires approval; with any other approver
    (e.g. a console), approval happens out of band and the client is never asked.

    The caller owns ``guard`` and must close it after the server stops.
    """
    info = await guard.describe()
    state = _State(guard=guard, elicits=isinstance(guard.approver, ElicitationApprover))

    @contextlib.asynccontextmanager
    async def lifespan(_: MCPServer[Any]) -> AsyncIterator[_State]:
        yield state

    server: MCPServer[Any] = MCPServer(
        name, version=__version__, instructions=INSTRUCTIONS, lifespan=lifespan
    )

    async def describe_soar(ctx: Context[Any, Any]) -> dict[str, Any]:
        """Describe the SOAR behind anysoar: which operations exist, their risk tier, and \
whether policy allows them, requires approval or denies them. Also reports the kill switch."""
        current = await guard.describe()
        switch = guard.kill_switch
        return {
            "driver": current.name,
            "soar_product": current.soar_product,
            "soar_version": current.soar_version,
            "kill_switch": {
                "engaged": bool(switch and switch.engaged),
                "reason": switch.reason if switch else None,
            },
            "operations": [
                {
                    "tool": c.value,
                    "tier": c.tier.value,
                    "policy": "per playbook (see list_playbooks)"
                    if c is Capability.RUN_PLAYBOOK
                    else guard.policy.decide_capability(c).value,
                }
                for c in sorted(current.capabilities)
            ],
        }

    server.add_tool(
        describe_soar,
        title="Describe SOAR",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    for capability in sorted(info.capabilities):
        fn = _TOOLS[capability]
        server.add_tool(
            fn,
            name=capability.value,
            title=capability.value.replace("_", " ").capitalize(),
            annotations=_annotations(capability),
        )
    return server


def _annotations(capability: Capability) -> ToolAnnotations:
    if capability.tier is ActionTier.READ:
        return ToolAnnotations(read_only_hint=True, open_world_hint=True)
    return ToolAnnotations(
        read_only_hint=False,
        destructive_hint=capability is Capability.RUN_PLAYBOOK,
        idempotent_hint=capability is Capability.CLOSE_CASE,
        open_world_hint=True,
    )


def _actor(ctx: Context[Any, Any]) -> str:
    params = ctx.session.client_params
    client = params.client_info.name if params is not None else None
    return f"mcp:{client or 'unknown-client'}"


def _can_elicit(ctx: Context[Any, Any]) -> bool:
    capabilities = ctx.client_capabilities
    elicitation = capabilities.elicitation if capabilities is not None else None
    # A bare `elicitation: {}` means form support; url-only does not.
    return elicitation is not None and (elicitation.form is not None or elicitation.url is None)


@contextlib.contextmanager
def _call_scope(ctx: Context[Any, Any], answer: object) -> Iterator[None]:
    actor_token = audit_actor.set(_actor(ctx))
    answer_token = _answer.set(answer)
    try:
        yield
    finally:
        _answer.reset(answer_token)
        audit_actor.reset(actor_token)


def _tool_error(exc: Exception) -> ToolError:
    if isinstance(exc, PolicyDeniedError):
        return ToolError(f"Denied by anysoar policy ({exc.reason.value}): {exc.detail}")
    if isinstance(exc, DriverError) and exc.retryable:
        return ToolError(f"SOAR error (retryable): {exc}")
    if isinstance(exc, DriverError):
        return ToolError(f"SOAR error: {exc}")
    return ToolError(str(exc))


_EXPECTED_ERRORS = (PolicyDeniedError, NotFoundError, CapabilityNotSupportedError, DriverError)


@dataclass(frozen=True)
class _State:
    guard: GuardedDriver
    elicits: bool


def _state(ctx: Context[Any, Any]) -> _State:
    state = ctx.request_context.lifespan_context
    assert isinstance(state, _State)
    return state


def _guard(ctx: Context[Any, Any]) -> GuardedDriver:
    return _state(ctx).guard


_Question = Elicit[ApprovalForm] | _NotAsked


async def _question(ctx: Context[Any, Any], capability: Capability, **kwargs: Any) -> _Question:
    """Ask the user only if this exact call needs approval and could still run."""
    state = _state(ctx)
    if not state.elicits:
        return _NotAsked(why="not_required")
    try:
        action = await state.guard.action(capability, **kwargs)
    except _EXPECTED_ERRORS:
        return _NotAsked(why="error")  # the tool body reports the real error
    switch = state.guard.kill_switch
    if state.guard.policy.decide(action) is not Decision.REQUIRE_APPROVAL or (
        switch is not None and switch.engaged
    ):
        return _NotAsked(why="not_required")
    if not _can_elicit(ctx):
        return _NotAsked(why="unsupported")
    message = (
        f"An AI agent wants to perform a {action.tier.value} action through anysoar:\n\n"
        f"{action.summary}\n\nApprove?"
    )
    return Elicit(message, ApprovalForm)


async def _run[T](ctx: Context[Any, Any], answer: object, call: Callable[[], Awaitable[T]]) -> T:
    with _call_scope(ctx, answer):
        try:
            return await call()
        except _EXPECTED_ERRORS as exc:
            raise _tool_error(exc) from exc


# Each tool has an approval resolver taking the same arguments, which the SDK runs before
# the tool body (see _question). Both build the driver call from the arguments the same way.

# -- Alerts -------------------------------------------------------------------------------

StatusArg = Annotated[
    list[AlertStatus] | None, Field(description="Only alerts with one of these statuses.")
]
SeverityArg = Annotated[Severity | None, Field(description="Only alerts at least this severe.")]
SinceArg = Annotated[
    datetime | None, Field(description="Only alerts created at or after this time (ISO 8601).")
]
UntilArg = Annotated[
    datetime | None, Field(description="Only alerts created before this time (ISO 8601).")
]
LimitArg = Annotated[int, Field(ge=1, le=100, description="Page size.")]
CursorArg = Annotated[str | None, Field(description="next_cursor from the previous page.")]
AlertUidArg = Annotated[str, Field(description="The alert's id (finding_info.uid).")]
CaseUidArg = Annotated[str, Field(description="The case's id (metadata.uid).")]


def _alert_query(
    status: list[AlertStatus] | None,
    min_severity: Severity | None,
    since: datetime | None,
    until: datetime | None,
    limit: int,
    cursor: str | None,
) -> AlertQuery:
    def ts(dt: datetime | None) -> int | None:
        return None if dt is None else to_timestamp(dt if dt.tzinfo else dt.replace(tzinfo=UTC))

    return AlertQuery(
        status_ids=frozenset(DetectionFindingStatusId[s.upper()] for s in status)
        if status
        else None,
        min_severity_id=SeverityId[min_severity.upper()] if min_severity else None,
        since=ts(since),
        until=ts(until),
        limit=limit,
        cursor=cursor,
    )


async def _ask_list_alerts(
    ctx: Context[Any, Any],
    status: StatusArg = None,
    min_severity: SeverityArg = None,
    since: SinceArg = None,
    until: UntilArg = None,
    limit: LimitArg = 20,
    cursor: CursorArg = None,
) -> _Question:
    query = _alert_query(status, min_severity, since, until, limit, cursor)
    return await _question(ctx, Capability.LIST_ALERTS, query=query)


async def list_alerts(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_list_alerts)],
    status: StatusArg = None,
    min_severity: SeverityArg = None,
    since: SinceArg = None,
    until: UntilArg = None,
    limit: LimitArg = 20,
    cursor: CursorArg = None,
) -> dict[str, Any]:
    """List alerts (OCSF Detection Findings), newest first. Page with next_cursor."""
    query = _alert_query(status, min_severity, since, until, limit, cursor)
    page = await _run(ctx, approval, lambda: _guard(ctx).list_alerts(query))
    return {"alerts": [a.to_ocsf() for a in page.items], "next_cursor": page.next_cursor}


async def _ask_get_alert(ctx: Context[Any, Any], alert_uid: AlertUidArg) -> _Question:
    return await _question(ctx, Capability.GET_ALERT, alert_uid=alert_uid)


async def get_alert(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_get_alert)],
    alert_uid: AlertUidArg,
) -> dict[str, Any]:
    """Get one alert (OCSF Detection Finding) with its observables and notes."""
    alert = await _run(ctx, approval, lambda: _guard(ctx).get_alert(alert_uid))
    return alert.to_ocsf()


# -- Cases --------------------------------------------------------------------------------


CaseStatusArg = Annotated[
    list[CaseStatus] | None, Field(description="Only cases with one of these statuses.")
]


def _case_query(status: list[CaseStatus] | None, limit: int, cursor: str | None) -> CaseQuery:
    return CaseQuery(
        status_ids=frozenset(IncidentFindingStatusId[s.upper()] for s in status)
        if status
        else None,
        limit=limit,
        cursor=cursor,
    )


async def _ask_list_cases(
    ctx: Context[Any, Any],
    status: CaseStatusArg = None,
    limit: LimitArg = 20,
    cursor: CursorArg = None,
) -> _Question:
    return await _question(ctx, Capability.LIST_CASES, query=_case_query(status, limit, cursor))


async def list_cases(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_list_cases)],
    status: CaseStatusArg = None,
    limit: LimitArg = 20,
    cursor: CursorArg = None,
) -> dict[str, Any]:
    """List cases (OCSF Incident Findings), most recently updated first. A case's id is its \
metadata.uid. Page with next_cursor."""
    query = _case_query(status, limit, cursor)
    page = await _run(ctx, approval, lambda: _guard(ctx).list_cases(query))
    return {"cases": [c.to_ocsf() for c in page.items], "next_cursor": page.next_cursor}


async def _ask_get_case(ctx: Context[Any, Any], case_uid: CaseUidArg) -> _Question:
    return await _question(ctx, Capability.GET_CASE, case_uid=case_uid)


async def get_case(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_get_case)],
    case_uid: CaseUidArg,
) -> dict[str, Any]:
    """Get one case (OCSF Incident Finding) with the alerts it groups and its notes."""
    case = await _run(ctx, approval, lambda: _guard(ctx).get_case(case_uid))
    return case.to_ocsf()


CommentArg = Annotated[str, Field(min_length=1, description="The note text.")]


async def _ask_add_note(
    ctx: Context[Any, Any], case_uid: CaseUidArg, comment: CommentArg, title: str | None = None
) -> _Question:
    note = Note(comment=comment, title=title)
    return await _question(ctx, Capability.ADD_NOTE, case_uid=case_uid, note=note)


async def add_note(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_add_note)],
    case_uid: CaseUidArg,
    comment: CommentArg,
    title: str | None = None,
) -> dict[str, Any]:
    """Add a note to a case. Needs approval under the default policy."""
    note = Note(comment=comment, title=title)
    stored = await _run(ctx, approval, lambda: _guard(ctx).add_note(case_uid, note))
    return stored.to_ocsf()


CloseCommentArg = Annotated[str | None, Field(description="Why the case is being closed.")]


async def _ask_close_case(
    ctx: Context[Any, Any],
    case_uid: CaseUidArg,
    verdict: Verdict,
    comment: CloseCommentArg = None,
) -> _Question:
    verdict_id = VerdictId[verdict.upper()]
    return await _question(
        ctx, Capability.CLOSE_CASE, case_uid=case_uid, verdict_id=verdict_id, comment=comment
    )


async def close_case(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_close_case)],
    case_uid: CaseUidArg,
    verdict: Verdict,
    comment: CloseCommentArg = None,
) -> dict[str, Any]:
    """Close a case with a verdict; most SOARs also resolve its alerts. Needs approval under \
the default policy."""
    verdict_id = VerdictId[verdict.upper()]
    case = await _run(
        ctx,
        approval,
        lambda: _guard(ctx).close_case(case_uid, verdict_id=verdict_id, comment=comment),
    )
    return case.to_ocsf()


# -- Indicators ---------------------------------------------------------------------------

IndicatorTypeArg = Annotated[
    IndicatorType, Field(description="OCSF observable type; use hostname for domains.")
]
IndicatorValueArg = Annotated[str, Field(min_length=1)]


async def _ask_enrich_indicator(
    ctx: Context[Any, Any], type: IndicatorTypeArg, value: IndicatorValueArg
) -> _Question:
    indicator = Observable(type_id=ObservableTypeId[type.upper()], value=value)
    return await _question(ctx, Capability.ENRICH_INDICATOR, indicator=indicator)


async def enrich_indicator(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_enrich_indicator)],
    type: IndicatorTypeArg,
    value: IndicatorValueArg,
) -> dict[str, Any]:
    """Look up reputation and context for an indicator using the SOAR's integrations."""
    indicator = Observable(type_id=ObservableTypeId[type.upper()], value=value)
    result = await _run(ctx, approval, lambda: _guard(ctx).enrich_indicator(indicator))
    return result.model_dump(mode="json", exclude_none=True)


# -- Playbooks ----------------------------------------------------------------------------


async def _ask_list_playbooks(ctx: Context[Any, Any]) -> _Question:
    return await _question(ctx, Capability.LIST_PLAYBOOKS)


async def list_playbooks(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_list_playbooks)],
) -> dict[str, Any]:
    """List playbooks, each with its risk tier and whether policy lets you run it (allow, \
require_approval or deny)."""
    guard = _guard(ctx)
    playbooks = await _run(ctx, approval, guard.list_playbooks)

    def policy(uid: str, tier: ActionTier) -> str:
        action = Action(
            capability=Capability.RUN_PLAYBOOK,
            tier=tier,
            summary=f"Run playbook {uid}",
            arguments={"playbook_uid": uid},
        )
        return guard.policy.decide(action).value

    return {
        "playbooks": [
            {**p.model_dump(mode="json", exclude_none=True), "policy": policy(p.uid, p.tier)}
            for p in playbooks
        ]
    }


CaseContextArg = Annotated[str | None, Field(description="Run in the context of this case.")]
AlertContextArg = Annotated[str | None, Field(description="Run in the context of this alert.")]
InputsArg = Annotated[
    dict[str, JsonValue] | None, Field(description="Inputs matching the playbook's input_schema.")
]


async def _ask_run_playbook(
    ctx: Context[Any, Any],
    playbook_uid: str,
    case_uid: CaseContextArg = None,
    alert_uid: AlertContextArg = None,
    inputs: InputsArg = None,
) -> _Question:
    return await _question(
        ctx,
        Capability.RUN_PLAYBOOK,
        playbook_uid=playbook_uid,
        case_uid=case_uid,
        alert_uid=alert_uid,
        inputs=inputs,
    )


async def run_playbook(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_run_playbook)],
    playbook_uid: str,
    case_uid: CaseContextArg = None,
    alert_uid: AlertContextArg = None,
    inputs: InputsArg = None,
) -> dict[str, Any]:
    """Start a playbook. Returns immediately; poll get_playbook_run until the status is \
succeeded, failed or cancelled. Needs approval under the default policy; destructive \
playbooks are denied."""
    run = await _run(
        ctx,
        approval,
        lambda: _guard(ctx).run_playbook(
            playbook_uid, case_uid=case_uid, alert_uid=alert_uid, inputs=inputs
        ),
    )
    return run.model_dump(mode="json", exclude_none=True)


async def _ask_get_playbook_run(ctx: Context[Any, Any], run_uid: str) -> _Question:
    return await _question(ctx, Capability.GET_PLAYBOOK_RUN, run_uid=run_uid)


async def get_playbook_run(
    ctx: Context[Any, Any],
    approval: Annotated[_Answer, Resolve(_ask_get_playbook_run)],
    run_uid: str,
) -> dict[str, Any]:
    """Get the status of a playbook run."""
    run = await _run(ctx, approval, lambda: _guard(ctx).get_playbook_run(run_uid))
    return run.model_dump(mode="json", exclude_none=True)


_TOOLS: dict[Capability, Callable[..., Awaitable[dict[str, Any]]]] = {
    Capability.LIST_ALERTS: list_alerts,
    Capability.GET_ALERT: get_alert,
    Capability.LIST_CASES: list_cases,
    Capability.GET_CASE: get_case,
    Capability.ADD_NOTE: add_note,
    Capability.CLOSE_CASE: close_case,
    Capability.ENRICH_INDICATOR: enrich_indicator,
    Capability.LIST_PLAYBOOKS: list_playbooks,
    Capability.RUN_PLAYBOOK: run_playbook,
    Capability.GET_PLAYBOOK_RUN: get_playbook_run,
}
