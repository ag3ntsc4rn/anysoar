"""A small async client for Shuffle's REST API that speaks anysoar's error types."""

from __future__ import annotations

from typing import Any

from anysoar._extras import missing_extra
from anysoar.errors import DriverError

try:
    import httpx2
except ModuleNotFoundError as exc:
    raise missing_extra("shuffle", exc) from exc

__all__ = ["ShuffleAPIError", "ShuffleClient"]

# Shuffle reports a missing object with these phrases, under 400 or 401 depending on the
# endpoint, so the status code alone cannot tell "not found" from "not allowed".
_NOT_FOUND_PHRASES = (
    "doesn't exist",
    "does not exist",
    "might not exist",
    "not found",
    "ID to execute is not valid",  # an id that is not a UUID
)


class ShuffleAPIError(DriverError):
    """Shuffle answered with an error (HTTP error status or ``{"success": false}``)."""

    def __init__(self, status: int, reason: str | None) -> None:
        self.status = status
        self.reason = reason
        detail = f": {reason}" if reason else ""
        retryable = status == 429 or status >= 500
        super().__init__(f"Shuffle API error {status}{detail}", retryable=retryable)

    @property
    def is_not_found(self) -> bool:
        return self.status == 404 or any(p in (self.reason or "") for p in _NOT_FOUND_PHRASES)


class ShuffleClient:
    """Sends authenticated requests to Shuffle and decodes JSON responses.

    Raises :class:`ShuffleAPIError` for error responses and :class:`DriverError` (marked
    retryable) for timeouts and connection failures, so no ``httpx2`` exception escapes.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 30.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._http = httpx2.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
            transport=transport,
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
                f"Shuffle request timed out: {method} {path}", retryable=True
            ) from exc
        except httpx2.TransportError as exc:
            raise DriverError(f"Could not reach Shuffle: {exc}", retryable=True) from exc
        try:
            body = response.json() if response.content else None
        except ValueError:
            body = None
        failed = isinstance(body, dict) and body.get("success") is False
        if response.status_code >= 400 or failed:
            reason = body.get("reason") if isinstance(body, dict) else None
            raise ShuffleAPIError(response.status_code, reason if isinstance(reason, str) else None)
        return body

    async def aclose(self) -> None:
        await self._http.aclose()
