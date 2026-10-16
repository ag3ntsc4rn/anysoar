"""The TheHive driver: TheHive alerts as anysoar alerts."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from anysoar import __version__
from anysoar.drivers.thehive import alerts
from anysoar.drivers.thehive.client import TheHiveAPIError, TheHiveClient
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import AlertQuery, Driver, DriverInfo, Page
from anysoar.models import DetectionFinding

if TYPE_CHECKING:
    import httpx2

__all__ = ["TheHiveDriver"]

_MAX_OBSERVABLES = 1000
"""The most observables get_alert returns for one alert."""


class TheHiveDriver(Driver):
    """Drives a TheHive 5 instance through its REST API (v1).

    Alerts are TheHive alerts (see :mod:`anysoar.drivers.thehive.alerts`); an alert's uid is
    its TheHive id, e.g. ``~8200``. Listing alerts leaves out their observables, which cost a
    query per alert; :meth:`get_alert` includes them.

    Args:
        base_url: TheHive's address, e.g. ``http://127.0.0.1:9000``. Defaults to the
            ``THEHIVE_URL`` environment variable.
        api_key: The API key of a TheHive user, ideally a service account with the analyst
            profile. Defaults to ``THEHIVE_API_KEY``.
        organisation: The organisation to work in, for users in several. Defaults to
            ``THEHIVE_ORGANISATION``, or the user's default organisation.
        timeout: Seconds to wait for each request.
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
        self._version: str | None = None

    async def describe(self) -> DriverInfo:
        if self._version is None:
            try:
                status = await self._client.request("GET", "/api/status")
            except DriverError:
                pass  # the version is nice to have; the real calls report what is wrong
            else:
                self._version = ((status or {}).get("versions") or {}).get("TheHive")
        return DriverInfo(
            name=self.name,
            capabilities=self.implemented_capabilities(),
            driver_version=__version__,
            soar_product="TheHive",
            soar_version=self._version,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

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
        alert = await self._get("alert", alert_uid)
        observables = await self._client.query(
            "anysoar-alert-observables",
            [
                {"_name": "getAlert", "idOrName": alert_uid},
                {"_name": "observables"},
                {"_name": "sort", "_fields": [{"_createdAt": "asc"}]},
                {"_name": "page", "from": 0, "to": _MAX_OBSERVABLES},
            ],
        )
        return alerts.to_alert(alert, observables)

    async def _get(self, kind: str, uid: str) -> dict[str, Any]:
        if not uid.startswith("~") or not uid[1:].isdigit():
            raise NotFoundError(kind, uid)  # TheHive ids look like ~8200
        try:
            found: dict[str, Any] = await self._client.request("GET", f"/api/v1/{kind}/{uid}")
        except TheHiveAPIError as exc:
            if exc.is_not_found:
                raise NotFoundError(kind, uid) from exc
            raise
        return found


def _offset(cursor: str | None) -> int:
    if cursor is None:
        return 0
    if not cursor.isdigit():
        raise DriverError(f"invalid cursor {cursor!r}")
    return int(cursor)
