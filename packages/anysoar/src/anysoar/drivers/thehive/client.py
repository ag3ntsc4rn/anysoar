"""A small async client for TheHive's REST API that speaks anysoar's error types."""

from __future__ import annotations

from typing import Any

from anysoar._extras import missing_extra
from anysoar.errors import DriverError

try:
    import httpx2
except ModuleNotFoundError as exc:
    raise missing_extra("thehive", exc) from exc

__all__ = ["TheHiveAPIError", "TheHiveClient"]


class TheHiveAPIError(DriverError):
    """TheHive answered with an HTTP error status."""

    def __init__(self, status: int, kind: str | None, reason: str | None) -> None:
        self.status = status
        self.kind = kind
        """TheHive's error type, e.g. ``NotFoundError`` or ``AuthorizationError``."""
        self.reason = reason
        detail = f": {reason}" if reason else ""
        retryable = status == 429 or status >= 500
        super().__init__(f"TheHive API error {status}{detail}", retryable=retryable)

    @property
    def is_not_found(self) -> bool:
        return self.status == 404


class TheHiveClient:
    """Sends authenticated requests to TheHive and decodes JSON responses.

    Raises :class:`TheHiveAPIError` for error responses and :class:`DriverError` (marked
    retryable) for timeouts and connection failures, so no ``httpx2`` exception escapes.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        organisation: str | None = None,
        timeout: float = 30.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"}
        if organisation:
            headers["X-Organisation"] = organisation
        self._http = httpx2.AsyncClient(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        try:
            response = await self._http.request(method, path, json=json, params=params)
        except httpx2.TimeoutException as exc:
            raise DriverError(
                f"TheHive request timed out: {method} {path}", retryable=True
            ) from exc
        except httpx2.TransportError as exc:
            raise DriverError(f"Could not reach TheHive: {exc}", retryable=True) from exc
        try:
            body = response.json() if response.content else None
        except ValueError:
            body = None
        if response.status_code >= 400:
            error = body if isinstance(body, dict) else {}
            raise TheHiveAPIError(
                response.status_code, error.get("type"), error.get("message") or None
            )
        return body

    async def query(self, name: str, operations: list[dict[str, Any]]) -> Any:
        """Run a query (``POST /api/v1/query``); ``name`` labels it in TheHive's logs."""
        return await self.request(
            "POST", "/api/v1/query", params={"name": name}, json={"query": operations}
        )

    async def aclose(self) -> None:
        await self._http.aclose()
