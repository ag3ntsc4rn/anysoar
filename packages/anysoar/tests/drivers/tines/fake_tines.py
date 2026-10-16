"""An in-memory stand-in for the Tines REST API, for tests.

Response shapes follow the examples in Tines' API reference (https://www.tines.com/api/):
lists are objects with the items under a named key and a ``meta`` page object, ids are
integers, times are ISO 8601 strings, and anything a key may not see is a 404.
"""

from __future__ import annotations

import itertools
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2

# Fake credentials, derived so no key-like literal sits in the source.
API_KEY = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://tines.test/fake-api-key"))
WEBHOOK_SECRET = uuid.uuid5(uuid.NAMESPACE_URL, "https://tines.test/fake-webhook").hex
BASE_URL = "https://tenant.tines.test"
TEAM_ID = 276

_T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def iso(minutes: int) -> str:
    return (_T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def person(user_id: int, first: str, email: str) -> dict[str, Any]:
    return {
        "user_id": str(user_id),
        "first_name": first,
        "last_name": "Analyst",
        "email": email,
        "avatar_url": "",
        "is_service_account": False,
    }


ANALYST = person(170, "Robin", "robin@example.com")
SERVICE = person(1, "anysoar", "anysoar-bot@example.com") | {"is_service_account": True}


def tines_case(
    case_id: int,
    name: str,
    *,
    status: str = "OPEN",
    sub_status: str = "To do",
    priority: str = "HIGH",
    updated: int = 0,
    tags: list[str] | None = None,
    assignees: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A case as GET /api/v2/cases/<id> returns it, trimmed of fields anysoar ignores."""
    return {
        "case_id": case_id,
        "name": name,
        "description": f"Synthetic case {case_id} reported by a user.",
        "status": status,
        "sub_status": {"id": 1, "name": sub_status},
        "priority": priority,
        "url": f"{BASE_URL}/team/{TEAM_ID}/cases/{case_id}",
        "metadata": {},
        "author": ANALYST,
        "opened_by": None,
        "resolved_by": None,
        "assignees": assignees if assignees is not None else [ANALYST],
        "tags": [{"id": i, "name": t} for i, t in enumerate(tags or [], start=1)],
        "activities": [],
        "team": {"id": TEAM_ID, "name": "SOC"},
        "opened_at": iso(0),
        "resolved_at": iso(updated) if status == "CLOSED" else None,
        "created_at": iso(0),
        "updated_at": iso(updated),
    }


@dataclass
class Run:
    story_id: int
    guid: str
    body: Any
    entry_event: int
    polls: int = 0
    exit_event: int | None = None
    created: datetime = field(default_factory=lambda: datetime.now(UTC))

    def at(self, seconds: int) -> str:
        return (self.created + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FakeTines:
    """Handles requests like Tines would. Use :meth:`transport` with the driver."""

    cases: dict[int, dict[str, Any]] = field(default_factory=dict)
    comments: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    stories: dict[int, dict[str, Any]] = field(default_factory=dict)
    actions: dict[int, dict[str, Any]] = field(default_factory=dict)
    runs: list[Run] = field(default_factory=list)
    requests: list[httpx2.Request] = field(default_factory=list)
    stalled_stories: set[int] = field(default_factory=set)
    """Stories whose runs never reach their exit action."""
    has_cases: bool = True
    """False for a tenant without Tines Cases, such as Community Edition."""

    def __post_init__(self) -> None:
        self._ids = itertools.count(1000)
        self.open_case = 42
        for case in (
            tines_case(42, 'Reported phishing: "Invoice INV-20431 overdue"', updated=30),
            tines_case(
                43,
                'Reported phishing: "Your mailbox is almost full"',
                sub_status="In progress",
                priority="CRITICAL",
                updated=20,
            ),
            tines_case(
                41,
                "Impossible travel for robin@example.com",
                status="CLOSED",
                sub_status="Resolved",
                priority="LOW",
                updated=10,
                tags=["phishing", "verdict:benign"],
                assignees=[],
            ),
        ):
            self.cases[case["case_id"]] = case
            self.comments[case["case_id"]] = []
        self.comment(43, "Users reported it twice.", ANALYST)

        self.block_sender = self.story("Block sender", description="Block a sender at the gateway")
        self.disable_account = self.story("Disable user account", tags=["anysoar:destructive"])
        self.public_lookup = self.story("Look up sender", secret=None)
        self.story("Not shared", send_to_story=False)
        self.story("Retired", disabled=True)

    def next_id(self) -> int:
        return next(self._ids)

    def comment(self, case_id: int, text: str, user: dict[str, Any]) -> dict[str, Any]:
        entry = {
            "id": self.next_id(),
            "activity_type": "COMMENTED",
            "value": text,
            "user": user,
            "created_at": iso(40 + len(self.comments[case_id])),
            "reactions": [],
        }
        self.comments[case_id].append(entry)
        return entry

    def story(
        self,
        name: str,
        *,
        description: str = "",
        tags: list[str] | None = None,
        secret: str | None = WEBHOOK_SECRET,
        send_to_story: bool = True,
        disabled: bool = False,
    ) -> int:
        story_id = self.next_id()
        entry, exit_ = self.next_id(), self.next_id()
        options: dict[str, Any] = {"path": uuid.uuid4().hex}
        if secret:
            options["secret"] = secret
        self.actions[entry] = {
            "id": entry,
            "type": "Agents::WebhookAgent",
            "name": "Webhook",
            "options": options,
            "story_id": story_id,
        }
        self.actions[exit_] = {
            "id": exit_,
            "type": "Agents::EventTransformationAgent",
            "name": "Exit",
            "options": {"mode": "message_only"},
            "story_id": story_id,
        }
        self.stories[story_id] = {
            "id": story_id,
            "name": name,
            "description": description,
            "disabled": disabled,
            "send_to_story_enabled": send_to_story,
            "send_to_story_timeout_enabled": True,
            "send_to_story_timeout_duration_seconds": 120,
            "entry_agent_id": entry if send_to_story else None,
            "exit_agents": [{"id": exit_}] if send_to_story else [],
            "team_id": TEAM_ID,
            "tags": tags or [],
            "mode": "LIVE",
        }
        return story_id

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else None
        if path.startswith("/webhook/"):
            return self._webhook(request, path.removeprefix("/webhook/"), body)
        if request.headers.get("Authorization") != f"Bearer {API_KEY}":
            return _json(401, {"error": "Unauthorized"})
        params = request.url.params

        if path.startswith("/api/v2/cases") and not self.has_cases:
            # What a Community Edition tenant answers (seen on a real one).
            return _json(401, ["This tenant does not have access to this feature"])
        if method == "GET" and path == "/api/v2/cases":
            return self._list_cases(params)
        if match := re.fullmatch(r"/api/v2/cases/(\d+)(/comments)?", path):
            case_id = int(match.group(1))
            if case_id not in self.cases:
                return _not_found()
            if match.group(2):
                if method == "POST":
                    return self._add_comment(case_id, body or {})
                return _json(
                    200, {"case_id": case_id, **_paged("comments", self.comments[case_id], params)}
                )
            if method == "PUT":
                self._update_case(case_id, body or {})
            return _json(200, self._case(case_id))
        if method == "GET" and path == "/api/v1/stories":
            stories = list(self.stories.values())
            if params.get("filter") == "SEND_TO_STORY_ENABLED":
                stories = [s for s in stories if s["send_to_story_enabled"]]
            return _json(200, _paged("stories", stories, params))
        if match := re.fullmatch(r"/api/v1/stories/(\d+)", path):
            story = self.stories.get(int(match.group(1)))
            return _json(200, story) if story else _not_found()
        if match := re.fullmatch(r"/api/v1/stories/(\d+)/runs/([\w-]+)", path):
            return self._run_events(int(match.group(1)), match.group(2), params)
        if match := re.fullmatch(r"/api/v1/actions/(\d+)", path):
            action = self.actions.get(int(match.group(1)))
            return _json(200, action) if action else _not_found()
        if match := re.fullmatch(r"/api/v1/actions/(\d+)/events", path):
            return self._action_events(int(match.group(1)), params)
        return _json(404, {"errors": [f"no route {method} {path}"]})

    def _case(self, case_id: int) -> dict[str, Any]:
        # Tines embeds the first page (20) of activities in a case.
        return self.cases[case_id] | {"activities": self.comments[case_id][:20]}

    def _list_cases(self, params: httpx2.QueryParams) -> httpx2.Response:
        ordered = sorted(self.cases, key=lambda c: self.cases[c]["updated_at"], reverse=True)
        return _json(200, _paged("cases", [self._case(c) for c in ordered], params))

    def _add_comment(self, case_id: int, body: dict[str, Any]) -> httpx2.Response:
        if not body.get("value"):
            return _json(422, {"errors": ["Value can't be blank"]})
        user = SERVICE
        if body.get("author_email") == ANALYST["email"]:
            user = ANALYST  # other emails are not on the team, so Tines uses the key's user
        return _json(201, {"case_id": case_id, **self.comment(case_id, body["value"], user)})

    def _update_case(self, case_id: int, body: dict[str, Any]) -> None:
        case = self.cases[case_id]
        names = [t["name"] for t in case["tags"]]
        names = [n for n in names if n not in body.get("remove_tag_names", [])]
        names += [n for n in body.get("add_tag_names", []) if n not in names]
        case["tags"] = [{"id": i, "name": n} for i, n in enumerate(names, start=1)]
        if "status" in body:
            case["status"] = body["status"].upper()
            closed = case["status"] == "CLOSED"
            case["sub_status"] = (
                {"id": 2, "name": "Resolved"} if closed else {"id": 1, "name": "To do"}
            )
            case["resolved_at"] = iso(90) if closed else None
        case["updated_at"] = iso(90)

    def _webhook(self, request: httpx2.Request, rest: str, body: Any) -> httpx2.Response:
        path, _, secret = rest.partition("/")
        action = next((a for a in self.actions.values() if a["options"].get("path") == path), None)
        if action is None or (action["options"].get("secret") or "") != secret:
            return _json(404, {"error": "Not found"})
        if not secret and request.headers.get("Authorization") != f"Bearer {API_KEY}":
            return _json(401, {"error": "Unauthorized"})
        run = Run(action["story_id"], str(uuid.uuid4()), body, self.next_id())
        self.runs.append(run)
        return httpx2.Response(201, text="Ok")

    def _action_events(self, action_id: int, params: httpx2.QueryParams) -> httpx2.Response:
        action = self.actions.get(action_id)
        if action is None:
            return _not_found()
        events = []
        for run in reversed(self.runs):  # newest first
            if run.story_id != action["story_id"]:
                continue
            if action["type"] == "Agents::WebhookAgent":
                run.polls += 1  # each poll lets the run take one step
                payload = {"body": run.body, "headers": {"content_type": "application/json"}}
                events.append(self._event(run.entry_event, action_id, run, payload))
            elif run.exit_event is not None:
                payload = {"exit": {"blocked": True, "sender": (run.body or {}).get("sender")}}
                if params.get("exclude_previous_event_payloads") != "true":
                    payload = {"webhook": {"body": run.body}, **payload}
                events.append(self._event(run.exit_event, action_id, run, payload))
        if since := params.get("since_id"):
            events = [e for e in events if e["id"] > int(since)]
        if until := params.get("until_id"):
            events = [e for e in events if e["id"] <= int(until)]
        return _json(200, _paged("events", events, params))

    def _run_events(self, story_id: int, guid: str, params: httpx2.QueryParams) -> httpx2.Response:
        run = next((r for r in self.runs if r.guid == guid and r.story_id == story_id), None)
        if run is None:
            return _not_found()
        entry = self.stories[story_id]["entry_agent_id"]
        events = [{"id": run.entry_event, "action_id": entry, "created_at": run.at(0)}]
        if run.polls >= 2 and story_id not in self.stalled_stories:
            if run.exit_event is None:
                run.exit_event = self.next_id()
            exit_id = self.stories[story_id]["exit_agents"][0]["id"]
            events.append({"id": run.exit_event, "action_id": exit_id, "created_at": run.at(1)})
        events = [e | {"is_reemitted": False} for e in events]
        return _json(200, _paged("story_run_events", events, params))

    @staticmethod
    def _event(event_id: int, action_id: int, run: Run, payload: Any) -> dict[str, Any]:
        return {
            "id": event_id,
            "agent_id": action_id,
            "payload": payload,
            "created_at": run.at(0),
            "updated_at": run.at(0),
            "story_run_guid": run.guid,
            "previous_events_ids": [],
            "re_emitted": False,
        }


def _paged(key: str, items: list[Any], params: httpx2.QueryParams) -> dict[str, Any]:
    per_page = int(params.get("per_page", "20"))
    page = int(params.get("page", "1"))
    pages = max(1, -(-len(items) // per_page))
    start = (page - 1) * per_page
    return {
        key: items[start : start + per_page],
        "meta": {
            "current_page": f"{BASE_URL}/api?per_page={per_page}&page={page}",
            "previous_page": None,
            "next_page": None,
            "next_page_number": page + 1 if page < pages else None,
            "per_page": per_page,
            "pages": pages,
            "count": len(items),
        },
    }


def _not_found() -> httpx2.Response:
    return _json(404, {"errors": ["Not found"]})


def _json(status: int, body: Any) -> httpx2.Response:
    return httpx2.Response(status, json=body)
