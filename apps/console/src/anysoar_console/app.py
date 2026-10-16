"""The console web app: an approval service for anysoar and a live view for people.

Two kinds of callers, with separate credentials:

- **anysoar** (``anysoar-mcp --approver http``) submits approval requests with the *submit
  token* (``Authorization: Bearer``), following :mod:`anysoar.policy.http_approver`. It can
  ask, never decide.
- **People** sign in by opening the one-time-printed login link, which sets a session
  cookie. Only a session can decide. Browser writes also need the ``X-Anysoar-Console``
  header, which other sites cannot send without a CORS preflight this app never allows.

The app listens on localhost only and rejects other Host headers (DNS rebinding).
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import secrets
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from anysoar.drivers import SoarSwitch
from anysoar.policy import KillSwitch
from anysoar_console.store import ApprovalStore, EventBus, Feed
from anysoar_console.watch import (
    follow_audit_log,
    soar_state,
    watch_kill_switch,
    watch_soar_switch,
)

__all__ = ["ConsoleConfig", "create_app"]

AGENT_EVENT_KINDS = {"start", "reasoning", "text", "tool_call", "tool_result", "done"}
SESSION_COOKIE = "anysoar_console"
CSRF_HEADER = "X-Anysoar-Console"
MAX_WAIT = 30.0


@dataclass
class ConsoleConfig:
    operator: str = "console"
    """Recorded as the approver of decisions made in this console."""
    submit_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    login_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    audit_log: Path | None = None
    """anysoar's audit log to show as it grows."""
    kill_switch: Path | None = None
    """anysoar's kill switch file, engaged and released from the console."""
    soar_switch: Path | None = None
    """anysoar's SOAR switch file (``anysoar-mcp --driver a,b``), switched from the console."""
    soars: tuple[str, ...] = ()
    """The SOARs anysoar can switch between, the first being the default."""


def _same(secret: str, candidate: str | None) -> bool:
    return candidate is not None and hmac.compare_digest(secret.encode(), candidate.encode())


def create_app(
    config: ConsoleConfig | None = None, *, on_shutdown: Callable[[], None] | None = None
) -> Starlette:
    """The console app. ``on_shutdown`` runs when the server stops, signals included."""
    config = config or ConsoleConfig()
    bus = EventBus()
    store = ApprovalStore(bus)
    agent_feed = Feed(bus, "agent")
    audit_feed = Feed(bus, "audit")
    switch = KillSwitch(config.kill_switch) if config.kill_switch else None
    soar_switch = (
        SoarSwitch(config.soar_switch, list(config.soars), default=config.soars[0])
        if config.soar_switch is not None and len(config.soars) > 1
        else None
    )
    sessions: set[str] = set()
    static = files("anysoar_console") / "static"

    def submitter(request: Request) -> bool:
        header = request.headers.get("Authorization", "")
        return _same(config.submit_token, header.removeprefix("Bearer ").strip() or None)

    def person(request: Request, *, writing: bool = False) -> bool:
        session = request.cookies.get(SESSION_COOKIE)
        signed_in = session is not None and any(_same(s, session) for s in sessions)
        return signed_in and (not writing or request.headers.get(CSRF_HEADER) == "1")

    denied = JSONResponse({"error": "not authorized"}, status_code=401)

    # -- Approval service (anysoar) --------------------------------------------------------

    async def submit(request: Request) -> Response:
        if not submitter(request):
            return denied
        body = await request.json()
        action = body.get("action")
        if not isinstance(action, dict) or not isinstance(action.get("summary"), str):
            return JSONResponse({"error": "action with a summary is required"}, status_code=400)
        actor = body.get("actor")
        approval = store.submit(action, actor if isinstance(actor, str) else None)
        return JSONResponse({"id": approval.id}, status_code=201)

    async def status(request: Request) -> Response:
        if not submitter(request):
            return denied
        try:
            wait = min(max(float(request.query_params.get("wait", "0")), 0.0), MAX_WAIT)
        except ValueError:
            wait = 0.0
        approval = await store.wait(request.path_params["id"], wait)
        if approval is None:
            return JSONResponse({"error": "no such approval"}, status_code=404)
        return JSONResponse(
            {"status": approval.status, "approver": approval.approver, "reason": approval.reason}
        )

    async def expire(request: Request) -> Response:
        if not submitter(request):
            return denied
        approval = store.expire(request.path_params["id"])
        if approval is None:
            return JSONResponse({"error": "no such approval"}, status_code=404)
        return JSONResponse({"status": approval.status})

    async def agent_event(request: Request) -> Response:
        # Agents report what they are doing. Their text is untrusted: the page only ever
        # renders it as text, and it is length-limited here.
        if not submitter(request):
            return denied
        body = await request.json()
        kind = body.get("kind")
        if kind not in AGENT_EVENT_KINDS:
            return JSONResponse({"error": "unknown event kind"}, status_code=400)
        event: dict[str, Any] = {"kind": kind, "time": _now()}
        for key, limit in (
            ("run", 100),
            ("text", 20_000),
            ("tool", 100),
            ("output", 4_000),
            ("case", 200),
            ("soar", 100),
        ):
            value = body.get(key)
            if isinstance(value, str):
                event[key] = value[:limit]
        arguments = body.get("arguments")
        if isinstance(arguments, dict):
            small = len(json.dumps(arguments)) <= 4_000
            event["arguments"] = arguments if small else {"truncated": True}
        if isinstance(body.get("ok"), bool):
            event["ok"] = body["ok"]
        agent_feed.add(event)
        return JSONResponse({"ok": True}, status_code=202)

    # -- People -----------------------------------------------------------------------------

    async def login(request: Request) -> Response:
        if not _same(config.login_token, request.query_params.get("token")):
            return HTMLResponse(
                _page("Sign-in link not valid. Use the link the console printed."), 401
            )
        session = secrets.token_urlsafe(32)
        sessions.add(session)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(SESSION_COOKIE, session, httponly=True, samesite="strict")
        return response

    async def index(request: Request) -> Response:
        if not person(request):
            return HTMLResponse(_page("Open the sign-in link printed by anysoar-console."), 401)
        return HTMLResponse((static / "index.html").read_text())

    async def state(request: Request) -> Response:
        if not person(request):
            return denied
        return JSONResponse(
            {
                "operator": config.operator,
                "approvals": [a.public() for a in store.all()],
                "agent": agent_feed.all(),
                "audit": audit_feed.all(),
                "kill_switch": _switch_state(switch),
                "soar": soar_state(soar_switch),
            }
        )

    async def switch_soar(request: Request) -> Response:
        if not person(request, writing=True):
            return denied
        if soar_switch is None:
            return JSONResponse({"error": "no SOAR switch configured"}, status_code=409)
        name = (await request.json()).get("soar")
        if name not in soar_switch.choices:
            return JSONResponse(
                {"error": f"soar must be one of {soar_switch.choices}"}, status_code=400
            )
        soar_switch.set(name)
        state = soar_state(soar_switch)
        bus.publish("soar", state)
        return JSONResponse(state)

    async def kill_switch(request: Request) -> Response:
        if not person(request, writing=True):
            return denied
        if switch is None or switch.path is None:
            return JSONResponse({"error": "no kill switch configured"}, status_code=409)
        body = await request.json()
        if body.get("engaged") is True:
            reason = body.get("reason")
            text = reason.strip()[:200] if isinstance(reason, str) and reason.strip() else ""
            switch.path.parent.mkdir(parents=True, exist_ok=True)
            switch.path.write_text(f"{text or 'stopped from the console'} ({config.operator})\n")
        elif body.get("engaged") is False:
            switch.path.unlink(missing_ok=True)
        else:
            return JSONResponse({"error": "engaged must be true or false"}, status_code=400)
        state = _switch_state(switch)
        bus.publish("kill_switch", state)
        return JSONResponse(state)

    async def decide(request: Request) -> Response:
        if not person(request, writing=True):
            return denied
        body = await request.json()
        decision = body.get("decision")
        if decision not in ("approve", "reject"):
            return JSONResponse({"error": "decision must be approve or reject"}, status_code=400)
        reason = body.get("reason")
        try:
            approval = store.decide(
                request.path_params["id"],
                approved=decision == "approve",
                approver=config.operator,
                reason=reason.strip() if isinstance(reason, str) else None,
            )
        except LookupError:
            return JSONResponse({"error": "no such approval"}, status_code=404)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse(approval.public())

    async def stream(request: Request) -> Response:
        if not person(request):
            return denied

        async def events() -> AsyncIterator[dict[str, str]]:
            async for event in bus.subscribe():
                yield {"event": event["kind"], "data": json.dumps(event)}

        return EventSourceResponse(events(), ping=15)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        tasks = []
        if config.audit_log is not None:
            tasks.append(asyncio.create_task(follow_audit_log(config.audit_log, audit_feed)))
        if switch is not None:
            tasks.append(asyncio.create_task(watch_kill_switch(switch, bus)))
        if soar_switch is not None:
            tasks.append(asyncio.create_task(watch_soar_switch(soar_switch, bus)))
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            if on_shutdown is not None:
                on_shutdown()

    app = Starlette(
        lifespan=lifespan,
        routes=[
            Route("/api/approvals", submit, methods=["POST"]),
            Route("/api/approvals/{id}", status, methods=["GET"]),
            Route("/api/approvals/{id}/expire", expire, methods=["POST"]),
            Route("/api/agent/events", agent_event, methods=["POST"]),
            Route("/login", login),
            Route("/", index),
            Route("/ui/state", state),
            Route("/ui/approvals/{id}/decide", decide, methods=["POST"]),
            Route("/ui/kill-switch", kill_switch, methods=["POST"]),
            Route("/ui/soar", switch_soar, methods=["POST"]),
            Route("/ui/stream", stream),
            Mount("/static", StaticFiles(directory=str(static)), name="static"),
        ],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=list(config.allowed_hosts))],
    )
    app.state.store = store
    app.state.bus = bus
    app.state.config = config
    return app


def _switch_state(switch: KillSwitch | None) -> dict[str, Any]:
    if switch is None:
        return {"available": False, "engaged": False, "reason": None}
    reason = switch.reason
    return {"available": True, "engaged": reason is not None, "reason": reason}


def _now() -> int:
    return int(time.time() * 1000)


def _page(message: str) -> str:
    return (
        "<!doctype html><meta charset=utf-8><title>anysoar console</title>"
        "<body style='font:16px system-ui;margin:3rem'>"
        f"<h1>anysoar console</h1><p>{message}</p></body>"
    )
