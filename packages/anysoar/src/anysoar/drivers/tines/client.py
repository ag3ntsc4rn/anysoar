"""A small async client for the Tines REST API that speaks anysoar's error types."""

from __future__ import annotations

from typing import Any

from anysoar._extras import missing_extra
from anysoar.errors import DriverError

try:
    import httpx2
except ModuleNotFoundError as exc:
    raise missing_extra("tines", exc) from exc

__all__ = ["TinesAPIError", "TinesClient"]


class TinesAPIError(DriverError):
    """Tines answered with an HTTP error status."""

    def __init__(self, status: int, reason: str | None) -> None:
        self.status = status
        self.reason = reason
        detail = f": {reason}" if reason else ""
        retryable = status == 429 or status >= 500
        super().__init__(f"Tines API error {status}{detail}", retryable=retryable)

    @property
    def is_not_found(self) -> bool:
        # Tines also answers 404 when the API key may not see the object.
        return self.status == 404


class TinesClient:
    """Sends authenticated requests to a Tines tenant and decodes JSON responses.

    Raises :class:`TinesAPIError` for error responses and :class:`DriverError` (marked
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
        authenticate: bool = True,
    ) -> Any:
        """Send a request. ``authenticate=False`` leaves out the API key, for webhooks that
        carry their own secret."""
        request = self._http.build_request(method, path, json=json, params=params)
        if not authenticate:
            del request.headers["Authorization"]
        try:
            response = await self._http.send(request)
        except httpx2.TimeoutException as exc:
            raise DriverError(f"Tines request timed out: {method} {path}", retryable=True) from exc
        except httpx2.TransportError as exc:
            raise DriverError(f"Could not reach Tines: {exc}", retryable=True) from exc
        try:
            body = response.json() if response.content else None
        except ValueError:
            body = None
        if response.status_code >= 400:
            raise TinesAPIError(response.status_code, _reason(body))
        return body

    async def aclose(self) -> None:
        await self._http.aclose()


def _reason(body: Any) -> str | None:
    """The error message in a Tines error body, which comes in a few shapes."""
    if not isinstance(body, dict):
        return None
    for key in ("error", "message", "errors"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list) and value:
            return "; ".join(str(v) for v in value)
    return None
