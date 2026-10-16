"""The Tines driver: Tines cases as anysoar cases, Send to Story stories as playbooks."""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from pydantic import JsonValue

from anysoar import __version__
from anysoar.drivers.tines import cases
from anysoar.drivers.tines.client import TinesAPIError, TinesClient
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import (
    ActionTier,
    Capability,
    CaseQuery,
    Driver,
    DriverInfo,
    Page,
    Playbook,
    PlaybookRun,
    PlaybookRunStatus,
)
from anysoar.models import IncidentFinding, Note, VerdictId, now_timestamp

if TYPE_CHECKING:
    import httpx2

    from anysoar.drivers import Retry

__all__ = ["DESTRUCTIVE_TAG", "TinesDriver"]

DESTRUCTIVE_TAG = "anysoar:destructive"
"""Tag a Tines story with this to mark it as a destructive playbook."""

_CASE_CAPABILITIES = frozenset(
    {Capability.LIST_CASES, Capability.GET_CASE, Capability.ADD_NOTE, Capability.CLOSE_CASE}
)
"""What needs Tines Cases, a paid feature that Community Edition tenants lack."""
_MAX_PER_PAGE = 500
"""The largest page Tines' list endpoints return."""
_RECENT_ENTRY_EVENTS = 100
"""How many of a story's latest entry events get_playbook_run searches for its run."""


class TinesDriver(Driver):
    """Drives a Tines tenant through its REST API.

    Cases are Tines cases (see :mod:`anysoar.drivers.tines.cases`); a case's uid is its
    case id. Tenants without Tines Cases, such as Community Edition, get playbooks only:
    :meth:`describe` checks once and leaves the case operations out.

    Playbooks are stories with Send to Story enabled, the stories Tines itself offers for
    other stories to call. A run posts to the story's entry webhook: a JSON object of the
    ``inputs``, plus an ``anysoar`` object with a ``run_uid`` and the ``case_uid`` and
    ``alert_uid`` the run is for, which the story reads as ``<<webhook.body.anysoar.case_uid>>``.
    Tines does not return a run id for a webhook call, so the driver finds the run by that
    ``run_uid`` among the entry action's events. A run succeeds when it reaches an exit
    action, whose output becomes the run's ``outputs["result"]``; it fails if the story's
    Send to Story timeout passes first. Tines has no notion of risk, so stories are
    ``WRITE`` tier unless tagged ``anysoar:destructive``.

    Args:
        base_url: The tenant's address, e.g. ``https://example-tenant.tines.com``. Defaults
            to the ``TINES_URL`` environment variable.
        api_key: A Tines API key. Defaults to ``TINES_API_KEY``.
        team_id: Only use this team's cases and stories. Defaults to ``TINES_TEAM_ID``, or
            every team the key can see.
        timeout: Seconds to wait for each request.
        retry: How to retry failed requests; by default up to three tries for those that
            are safe to repeat (see :class:`~anysoar.drivers.Retry`).
        transport: An ``httpx2`` transport, for tests.
    """

    name = "tines"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        team_id: int | str | None = None,
        timeout: float = 30.0,
        retry: Retry | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        base_url = base_url or os.environ.get("TINES_URL")
        api_key = api_key or os.environ.get("TINES_API_KEY")
        if not base_url or not api_key:
            raise ValueError("Tines needs a base_url and api_key (or TINES_URL and TINES_API_KEY)")
        team = team_id if team_id is not None else os.environ.get("TINES_TEAM_ID") or None
        if team is not None and not str(team).isdigit():
            raise ValueError(f"team_id must be a Tines team id (a number), not {team!r}")
        self._team = str(team) if team is not None else None
        self._client = TinesClient(
            base_url, api_key, timeout=timeout, retry=retry, transport=transport
        )
        self._has_cases: bool | None = None

    async def describe(self) -> DriverInfo:
        capabilities = self.implemented_capabilities()
        if not await self._cases_available():
            capabilities -= _CASE_CAPABILITIES
        return DriverInfo(
            name=self.name,
            capabilities=capabilities,
            driver_version=__version__,
            soar_product="Tines",
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _team_params(self) -> dict[str, str]:
        return {"team_id": self._team} if self._team else {}

    async def _cases_available(self) -> bool:
        """Whether the tenant has Tines Cases. Assumed so if Tines cannot be asked."""
        if self._has_cases is None:
            try:
                await self._client.request(
                    "GET", "/api/v2/cases", params={"per_page": "1", **self._team_params()}
                )
            except TinesAPIError as exc:
                if not exc.is_feature_unavailable:
                    return True  # e.g. a bad key: let the real call report it
                self._has_cases = False
            else:
                self._has_cases = True
        return self._has_cases

    def _no_cases(self, exc: TinesAPIError, capability: Capability) -> Exception:
        if exc.is_feature_unavailable:
            self._has_cases = False
            return self._unsupported(capability)
        return exc

    # -- Cases ----------------------------------------------------------------------------

    async def list_cases(self, query: CaseQuery | None = None) -> Page[IncidentFinding]:
        query = query or CaseQuery()
        page = _page_number(query.cursor)
        try:
            listing = await self._client.request(
                "GET",
                "/api/v2/cases",
                params={
                    "order": "RECENTLY_EDITED",
                    "per_page": str(query.limit),
                    "page": str(page),
                    **self._team_params(),
                },
            )
        except TinesAPIError as exc:
            raise self._no_cases(exc, Capability.LIST_CASES) from exc
        # OCSF statuses come partly from sub-status names, which Tines cannot filter on, so
        # filter here; a page can then hold fewer than ``limit`` cases.
        found = [cases.to_case(c) for c in listing.get("cases") or []]
        if query.status_ids is not None:
            found = [c for c in found if c.status_id in query.status_ids]
        found.sort(key=lambda c: c.time, reverse=True)
        next_page = (listing.get("meta") or {}).get("next_page_number")
        return Page(items=found, next_cursor=str(next_page) if next_page else None)

    async def get_case(self, case_uid: str) -> IncidentFinding:
        case = await self._case(case_uid, Capability.GET_CASE)
        comments = await self._comments(case_uid, Capability.GET_CASE)
        return cases.to_case(case, comments)

    async def add_note(self, case_uid: str, note: Note) -> Note:
        body: dict[str, Any] = {"value": note.comment}
        if note.owner and note.owner.email_addr:
            # Tines falls back to the API key's user if this person is not on the team.
            body["author_email"] = note.owner.email_addr
        created = await self._case_request(
            "POST", case_uid, Capability.ADD_NOTE, "/comments", json=body
        )
        stored = cases.to_note(created)
        return note.model_copy(
            update={
                "uid": stored.uid,
                "created_time": stored.created_time or note.created_time,
                "owner": stored.owner or note.owner,
            }
        )

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        case = await self._case(case_uid, Capability.CLOSE_CASE)
        tag = cases.verdict_tag(verdict_id)
        stale = [
            t for t in cases.tag_names(case) if t.startswith(cases.VERDICT_TAG_PREFIX) and t != tag
        ]
        update: dict[str, Any] = {"status": "closed", "add_tag_names": [tag]}
        if stale:
            update["remove_tag_names"] = stale
        await self._case_request("PUT", case_uid, Capability.CLOSE_CASE, json=update)
        # Tines has no closing comment; record the verdict and reason as a comment.
        text = f"Closed as {cases.verdict_label(verdict_id)}."
        if comment:
            text = f"{text}\n\n{comment}"
        await self._case_request(
            "POST", case_uid, Capability.CLOSE_CASE, "/comments", json={"value": text}
        )
        return await self.get_case(case_uid)

    async def _case(self, case_uid: str, capability: Capability) -> dict[str, Any]:
        case: dict[str, Any] = await self._case_request("GET", case_uid, capability)
        return case

    async def _comments(self, case_uid: str, capability: Capability) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        page: int | None = 1
        while page:
            listing = await self._case_request(
                "GET",
                case_uid,
                capability,
                "/comments",
                params={"per_page": str(_MAX_PER_PAGE), "page": str(page)},
            )
            comments += listing.get("comments") or []
            page = (listing.get("meta") or {}).get("next_page_number")
        return comments

    async def _case_request(
        self,
        method: str,
        case_uid: str,
        capability: Capability,
        suffix: str = "",
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        if not case_uid.isdigit():
            raise NotFoundError("case", case_uid)  # Tines case ids are numbers
        try:
            return await self._client.request(
                method, f"/api/v2/cases/{case_uid}{suffix}", json=json, params=params
            )
        except TinesAPIError as exc:
            if exc.is_feature_unavailable:
                raise self._no_cases(exc, capability) from exc
            raise _not_found_or(exc, "case", case_uid) from exc

    # -- Playbooks ------------------------------------------------------------------------

    async def list_playbooks(self) -> list[Playbook]:
        playbooks: list[Playbook] = []
        page: int | None = 1
        while page:
            listing = await self._client.request(
                "GET",
                "/api/v1/stories",
                params={
                    "filter": "SEND_TO_STORY_ENABLED",
                    "per_page": str(_MAX_PER_PAGE),
                    "page": str(page),
                    **self._team_params(),
                },
            )
            playbooks += [
                _to_playbook(s)
                for s in listing.get("stories") or []
                if s.get("send_to_story_enabled") and s.get("entry_agent_id")
                if not s.get("disabled")
            ]
            page = (listing.get("meta") or {}).get("next_page_number")
        return playbooks

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        story = await self._story(playbook_uid, "playbook", playbook_uid)
        if story.get("disabled"):
            raise DriverError(f"Tines story {playbook_uid} is disabled")
        entry = story.get("entry_agent_id")
        if not story.get("send_to_story_enabled") or not entry:
            raise DriverError(
                f"Tines story {playbook_uid} cannot be run by anysoar: enable Send to Story"
            )
        action = await self._client.request("GET", f"/api/v1/actions/{entry}")
        options = action.get("options") or {}
        path = options.get("path")
        if not path:
            raise DriverError(f"the entry action of Tines story {playbook_uid} is not a webhook")

        token = uuid.uuid4().hex
        context = {"run_uid": token, "case_uid": case_uid, "alert_uid": alert_uid}
        body = {**(inputs or {}), "anysoar": {k: v for k, v in context.items() if v}}
        secret = options.get("secret")
        if secret:
            await self._client.request(
                "POST", f"/webhook/{path}/{secret}", json=body, authenticate=False
            )
        else:
            # A webhook without a secret is either public or restricted to API keys.
            await self._client.request("POST", f"/webhook/{path}", json=body)
        return PlaybookRun(
            uid=f"{playbook_uid}:{token}",
            playbook_uid=playbook_uid,
            status=PlaybookRunStatus.QUEUED,
            started_time=now_timestamp(),
        )

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        story_id, _, token = run_uid.partition(":")
        if not story_id.isdigit() or len(token) != 32:
            raise NotFoundError("playbook run", run_uid)
        story = await self._story(story_id, "playbook run", run_uid)
        entry = story.get("entry_agent_id")
        started = None
        if entry:
            events = await self._client.request(
                "GET",
                f"/api/v1/actions/{entry}/events",
                params={"per_page": str(_RECENT_ENTRY_EVENTS)},
            )
            started = next(
                (e for e in events.get("events") or [] if _carries(e.get("payload"), token)),
                None,
            )
        run = PlaybookRun(uid=run_uid, playbook_uid=story_id, status=PlaybookRunStatus.QUEUED)
        if started is None:
            return run  # Tines has not processed the webhook call yet
        started_time = cases.timestamp(started.get("created_at"))
        run = run.model_copy(
            update={"status": PlaybookRunStatus.RUNNING, "started_time": started_time}
        )

        exits = _exit_action_ids(story)
        guid = started.get("story_run_guid")
        finished = None
        if guid and exits:
            run_events = await self._client.request(
                "GET",
                f"/api/v1/stories/{story_id}/runs/{guid}",
                params={"per_page": str(_MAX_PER_PAGE)},
            )
            finished = next(
                (
                    e
                    for e in run_events.get("story_run_events") or []
                    if e.get("action_id") in exits
                ),
                None,
            )
        if finished is not None:
            emitted = await self._exit_event(finished)
            # Run events give whole seconds; the exit event itself has milliseconds.
            ended = cases.timestamp((emitted or finished).get("created_at"))
            if ended is not None and started_time is not None:
                ended = max(ended, started_time)
            return run.model_copy(
                update={
                    "status": PlaybookRunStatus.SUCCEEDED,
                    "ended_time": ended,
                    "outputs": {"result": _exit_output(emitted)},
                }
            )
        limit = story.get("send_to_story_timeout_duration_seconds")
        timed_out = (
            story.get("send_to_story_timeout_enabled")
            and isinstance(limit, int)
            and started_time is not None
            and now_timestamp() - started_time > limit * 1000
        )
        if timed_out:
            return run.model_copy(
                update={
                    "status": PlaybookRunStatus.FAILED,
                    "message": f"no exit action reached within the story's {limit}s timeout",
                }
            )
        return run

    async def _story(self, story_id: str, kind: str, uid: str) -> dict[str, Any]:
        if not story_id.isdigit():
            raise NotFoundError(kind, uid)  # Tines story ids are numbers
        try:
            story: dict[str, Any] = await self._client.request("GET", f"/api/v1/stories/{story_id}")
        except TinesAPIError as exc:
            raise _not_found_or(exc, kind, uid) from exc
        if self._team and str(story.get("team_id")) != self._team:
            raise NotFoundError(kind, uid)
        return story

    async def _exit_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """The event the exit action emitted, without its upstream events' payloads."""
        event_id = int(event["id"])
        listing = await self._client.request(
            "GET",
            f"/api/v1/actions/{event['action_id']}/events",
            params={
                "since_id": str(event_id - 1),
                "until_id": str(event_id),
                "exclude_previous_event_payloads": "true",
                "per_page": "1",
            },
        )
        for emitted in listing.get("events") or []:
            if emitted.get("id") == event_id:
                found: dict[str, Any] = emitted
                return found
        return None


def _page_number(cursor: str | None) -> int:
    if cursor is None:
        return 1
    if not cursor.isdigit() or int(cursor) < 1:
        raise DriverError(f"invalid cursor {cursor!r}")
    return int(cursor)


def _not_found_or(exc: TinesAPIError, kind: str, uid: str) -> Exception:
    return NotFoundError(kind, uid) if exc.is_not_found else exc


def _to_playbook(story: dict[str, Any]) -> Playbook:
    tags = story.get("tags") or []
    return Playbook(
        uid=str(story["id"]),
        name=story.get("name") or str(story["id"]),
        description=story.get("description") or None,
        tier=ActionTier.DESTRUCTIVE if DESTRUCTIVE_TAG in tags else ActionTier.WRITE,
    )


def _exit_action_ids(story: dict[str, Any]) -> set[int]:
    exits = story.get("exit_agents") or []
    ids = [e.get("id") if isinstance(e, dict) else e for e in exits]
    ids += story.get("exit_agent_ids") or []
    return {int(i) for i in ids if isinstance(i, int | str) and str(i).isdigit()}


def _exit_output(event: dict[str, Any] | None) -> JsonValue:
    """What the exit action emitted. Tines keys an event's payload by the action's name,
    e.g. ``{"exit": {"ok": true}}``; the run's result is the value under that name."""
    payload: JsonValue = (event or {}).get("payload")
    if isinstance(payload, dict) and len(payload) == 1:
        (payload,) = payload.values()
    return payload


def _carries(payload: Any, token: str, depth: int = 4) -> bool:
    """Whether an event payload holds ``anysoar.run_uid == token``.

    The webhook's request body sits under ``body``, possibly nested under the action's
    name, so look a few levels down.
    """
    if not isinstance(payload, dict) or depth == 0:
        return False
    marker = payload.get("anysoar")
    if isinstance(marker, dict) and marker.get("run_uid") == token:
        return True
    return any(_carries(v, token, depth - 1) for v in payload.values())
