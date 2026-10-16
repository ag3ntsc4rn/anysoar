"""The TheHive driver: TheHive alerts and cases, and Cortex analyzers for enrichment."""

from __future__ import annotations

import asyncio
import heapq
import os
import time
from typing import TYPE_CHECKING, Any

from anysoar import __version__
from anysoar.drivers.thehive import alerts, cases, enrichment
from anysoar.drivers.thehive.client import TheHiveAPIError, TheHiveClient
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import (
    AlertQuery,
    Capability,
    CaseQuery,
    Driver,
    DriverInfo,
    IndicatorEnrichment,
    Page,
)
from anysoar.models import DetectionFinding, IncidentFinding, Note, Observable, VerdictId

if TYPE_CHECKING:
    import httpx2

__all__ = ["TheHiveDriver"]

_MAX_RELATED = 1000
"""The most observables, comments or alerts get_alert and get_case return for one record."""


class TheHiveDriver(Driver):
    """Drives a TheHive 5 instance through its REST API (v1).

    Alerts are TheHive alerts (see :mod:`anysoar.drivers.thehive.alerts`); an alert's uid is
    its TheHive id, e.g. ``~8200``. Cases are TheHive cases (see
    :mod:`anysoar.drivers.thehive.cases`); a case's uid is its number, e.g. ``42``. Listing
    leaves out observables, comments and a case's alerts, which cost queries per record;
    :meth:`get_alert` and :meth:`get_case` include them.

    :meth:`enrich_indicator` runs Cortex analyzers through TheHive, which runs them only on
    observables of its alerts and cases: it finds the newest observable with the indicator's
    type and value, runs every analyzer for that type on it and waits for the reports (see
    :mod:`anysoar.drivers.thehive.enrichment`). An indicator TheHive has no observable for
    gets no enrichments. Instances without Cortex analyzers do not offer enrichment.

    Args:
        base_url: TheHive's address, e.g. ``http://127.0.0.1:9000``. Defaults to the
            ``THEHIVE_URL`` environment variable.
        api_key: The API key of a TheHive user, ideally a service account with the analyst
            profile. Defaults to ``THEHIVE_API_KEY``.
        organisation: The organisation to work in, for users in several. Defaults to
            ``THEHIVE_ORGANISATION``, or the user's default organisation.
        timeout: Seconds to wait for each request.
        enrich_timeout: Seconds :meth:`enrich_indicator` waits for analyzers to finish.
        poll_interval: Seconds between checks on running analyzers.
        transport: An ``httpx2`` transport, for tests.
    """

    name = "thehive"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        organisation: str | None = None,
        timeout: float = 30.0,
        enrich_timeout: float = 60.0,
        poll_interval: float = 2.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        base_url = base_url or os.environ.get("THEHIVE_URL")
        api_key = api_key or os.environ.get("THEHIVE_API_KEY")
        if not base_url or not api_key:
            raise ValueError(
                "TheHive needs a base_url and api_key (or THEHIVE_URL and THEHIVE_API_KEY)"
            )
        self._client = TheHiveClient(
            base_url,
            api_key,
            organisation=organisation or os.environ.get("THEHIVE_ORGANISATION") or None,
            timeout=timeout,
            transport=transport,
        )
        self._enrich_timeout = enrich_timeout
        self._poll_interval = poll_interval
        self._version: str | None = None
        self._has_analyzers: bool | None = None

    async def describe(self) -> DriverInfo:
        if self._version is None:
            try:
                status = await self._client.request("GET", "/api/status")
            except DriverError:
                pass  # the version is nice to have; the real calls report what is wrong
            else:
                self._version = ((status or {}).get("versions") or {}).get("TheHive")
        capabilities = self.implemented_capabilities()
        if not await self._analyzers_available():
            capabilities -= {Capability.ENRICH_INDICATOR}
        return DriverInfo(
            name=self.name,
            capabilities=capabilities,
            driver_version=__version__,
            soar_product="TheHive",
            soar_version=self._version,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _analyzers_available(self) -> bool:
        """Whether TheHive has Cortex analyzers to run. Assumed so if it cannot be asked."""
        if self._has_analyzers is None:
            try:
                found = await self._client.request("GET", "/api/v1/connector/cortex/analyzer")
            except TheHiveAPIError as exc:
                if not exc.is_not_found:
                    return True  # e.g. a bad key: let the real call report it
                found = []  # the Cortex connector is turned off
            except DriverError:
                return True
            self._has_analyzers = bool(found)
        return self._has_analyzers

    # -- Alerts ---------------------------------------------------------------------------

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        query = query or AlertQuery()
        start = _offset(query.cursor)
        conditions: list[dict[str, Any]] = []
        if query.status_ids is not None:
            conditions.append(alerts.alert_status_filter(query.status_ids))
        if query.min_severity_id is not None:
            severity = alerts.min_severity(query.min_severity_id)
            conditions.append({"_gte": {"_field": "severity", "_value": severity}})
        if query.since is not None:
            conditions.append({"_gte": {"_field": "_createdAt", "_value": query.since}})
        if query.until is not None:
            conditions.append({"_lt": {"_field": "_createdAt", "_value": query.until}})
        operations: list[dict[str, Any]] = [{"_name": "listAlert"}]
        if conditions:
            operations.append({"_name": "filter", "_and": conditions})
        operations += [
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}, {"_id": "desc"}]},
            # One more than asked for, to tell whether there is a next page.
            {"_name": "page", "from": start, "to": start + query.limit + 1},
        ]
        found = await self._client.query("anysoar-list-alerts", operations)
        more = len(found) > query.limit
        return Page(
            items=[alerts.to_alert(a) for a in found[: query.limit]],
            next_cursor=str(start + query.limit) if more else None,
        )

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        if not alert_uid.startswith("~") or not alert_uid[1:].isdigit():
            raise NotFoundError("alert", alert_uid)  # TheHive ids look like ~8200
        alert = await self._get("alert", alert_uid)
        observables = await self._client.query(
            "anysoar-alert-observables",
            [
                {"_name": "getAlert", "idOrName": alert_uid},
                {"_name": "observables"},
                *_OLDEST_FIRST,
            ],
        )
        return alerts.to_alert(alert, observables)

    # -- Cases ----------------------------------------------------------------------------

    async def list_cases(self, query: CaseQuery | None = None) -> Page[IncidentFinding]:
        query = query or CaseQuery()
        updated_from, fresh_from = _case_offsets(query.cursor)
        status = [] if query.status_ids is None else [cases.case_status_filter(query.status_ids)]
        has_update = {"_has": "_updatedAt"}
        # A case's time is when it was last updated, or created if it never was. TheHive
        # sorts cases it never updated last, so list the two kinds apart and merge them.
        updated = await self._list_cases(
            [has_update, *status], "_updatedAt", updated_from, query.limit
        )
        fresh = await self._list_cases(
            [{"_not": has_update}, *status], "_createdAt", fresh_from, query.limit
        )
        merged = list(heapq.merge(updated, fresh, key=_case_order, reverse=True))
        page = merged[: query.limit]
        taken_updated = sum(1 for c in page if c.get("_updatedAt"))
        more = len(merged) > query.limit
        return Page(
            items=[cases.to_case(c) for c in page],
            next_cursor=(
                f"{updated_from + taken_updated}:{fresh_from + len(page) - taken_updated}"
                if more
                else None
            ),
        )

    async def _list_cases(
        self, conditions: list[dict[str, Any]], time_field: str, start: int, limit: int
    ) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = await self._client.query(
            "anysoar-list-cases",
            [
                {"_name": "listCase"},
                {"_name": "filter", "_and": conditions},
                {"_name": "sort", "_fields": [{time_field: "desc"}, {"number": "desc"}]},
                # One more than asked for, to tell whether there is a next page.
                {"_name": "page", "from": start, "to": start + limit + 1},
            ],
        )
        return found

    async def get_case(self, case_uid: str) -> IncidentFinding:
        case = await self._case(case_uid)
        related = {}
        for kind in ("comments", "alerts", "observables"):
            related[kind] = await self._client.query(
                f"anysoar-case-{kind}",
                [{"_name": "getCase", "idOrName": case_uid}, {"_name": kind}, *_OLDEST_FIRST],
            )
        return cases.to_case(case, **related)

    async def add_note(self, case_uid: str, note: Note) -> Note:
        await self._case(case_uid)
        comment = await self._client.request(
            "POST", f"/api/v1/case/{case_uid}/comment", json={"message": note.comment}
        )
        stored = cases.to_note(comment)
        # TheHive writes comments as the API key's user, whoever the note names.
        return note.model_copy(
            update={
                "uid": stored.uid,
                "owner": stored.owner or note.owner,
                "created_time": stored.created_time or note.created_time,
            }
        )

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        case = await self._case(case_uid)
        status, tags = cases.closing(verdict_id, [str(t) for t in case.get("tags") or []])
        update: dict[str, Any] = {"status": status, "tags": tags}
        if comment:
            update["summary"] = comment
        await self._client.request("PATCH", f"/api/v1/case/{case_uid}", json=update)
        return await self.get_case(case_uid)

    async def _case(self, case_uid: str) -> dict[str, Any]:
        if not case_uid.isdigit():
            raise NotFoundError("case", case_uid)  # anysoar uses case numbers, e.g. 42
        return await self._get("case", case_uid)

    # -- Indicators -----------------------------------------------------------------------

    async def enrich_indicator(self, indicator: Observable) -> IndicatorEnrichment:
        result = IndicatorEnrichment(observable=indicator.model_copy(deep=True))
        types = enrichment.data_types(indicator)
        if indicator.value is None or not types:
            return result
        found = await self._client.query(
            "anysoar-find-observable",
            [
                {"_name": "listObservable"},
                {
                    "_name": "filter",
                    "_and": [
                        {"_in": {"_field": "dataType", "_values": types}},
                        {"_eq": {"_field": "data", "_value": indicator.value}},
                    ],
                },
                {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                {"_name": "page", "from": 0, "to": 1},
            ],
        )
        if not found:
            return result  # TheHive can only analyze indicators on its alerts and cases
        observable = found[0]
        analyzers = await self._client.request(
            "GET", f"/api/v1/connector/cortex/analyzer/type/{observable['dataType']}"
        )
        jobs = []
        for analyzer in analyzers:
            body = {"analyzerId": analyzer["id"], "artifactId": observable["_id"]}
            cortex_ids = analyzer.get("cortexIds") or []
            if cortex_ids:
                body["cortexId"] = cortex_ids[0]
            jobs.append(
                await self._client.request("POST", "/api/v1/connector/cortex/job", json=body)
            )
        jobs = await self._wait_for(jobs)

        reports: dict[str, Any] = {}
        if jobs:  # the taxonomies are on the observable, by analyzer name
            refreshed = await self._client.request("GET", f"/api/v1/observable/{observable['_id']}")
            reports = refreshed.get("reports") or {}
        taxonomies = [enrichment.taxonomies(job, reports) for job in jobs]
        name = indicator.name or observable["dataType"]
        return IndicatorEnrichment(
            observable=result.observable.model_copy(
                update={"reputation": enrichment.reputation([t for ts in taxonomies for t in ts])}
            ),
            enrichments=[
                enrichment.to_enrichment(job, found, name=name, value=indicator.value)
                for job, found in zip(jobs, taxonomies, strict=True)
            ],
        )

    async def _wait_for(self, jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The jobs once all have finished, or as they are when the enrich timeout passes."""
        deadline = time.monotonic() + self._enrich_timeout
        while True:
            jobs = [
                job
                if job.get("status") in _FINISHED_JOBS
                else await self._client.request("GET", f"/api/v1/connector/cortex/job/{job['_id']}")
                for job in jobs
            ]
            if all(j.get("status") in _FINISHED_JOBS for j in jobs):
                return jobs
            if time.monotonic() >= deadline:
                return jobs
            await asyncio.sleep(self._poll_interval)

    async def _get(self, kind: str, uid: str) -> dict[str, Any]:
        try:
            found: dict[str, Any] = await self._client.request("GET", f"/api/v1/{kind}/{uid}")
        except TheHiveAPIError as exc:
            if exc.is_not_found:
                raise NotFoundError(kind, uid) from exc
            raise
        return found


_FINISHED_JOBS = {"Success", "Failure"}

_OLDEST_FIRST = (
    {"_name": "sort", "_fields": [{"_createdAt": "asc"}]},
    {"_name": "page", "from": 0, "to": _MAX_RELATED},
)


def _case_order(case: dict[str, Any]) -> tuple[int, int]:
    return case.get("_updatedAt") or case.get("_createdAt") or 0, int(case.get("number") or 0)


def _case_offsets(cursor: str | None) -> tuple[int, int]:
    """Offsets into the updated and never-updated cases, from a ``"<n>:<n>"`` cursor."""
    if cursor is None:
        return 0, 0
    updated, _, fresh = cursor.partition(":")
    if not (updated.isdigit() and fresh.isdigit()):
        raise DriverError(f"invalid cursor {cursor!r}")
    return int(updated), int(fresh)


def _offset(cursor: str | None) -> int:
    if cursor is None:
        return 0
    if not cursor.isdigit():
        raise DriverError(f"invalid cursor {cursor!r}")
    return int(cursor)
