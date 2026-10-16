"""Sending HTTP requests to a SOAR with retries (see :class:`~anysoar.drivers.Retry`),
shared by the HTTP drivers.
"""

from __future__ import annotations

import httpx2

from anysoar.drivers.retry import Retry
from anysoar.errors import DriverError

__all__ = ["send"]

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_RETRY_STATUSES = frozenset({500, 502, 503, 504})


async def send(
    http: httpx2.AsyncClient,
    request: httpx2.Request,
    *,
    product: str,
    retry: Retry,
    idempotent: bool | None = None,
) -> httpx2.Response:
    """Send ``request``, retrying as the module describes, and return the last response.

    Error statuses are returned for the caller to interpret. Failures without a response
    raise :class:`DriverError`, marked retryable. ``idempotent`` defaults to what the
    request's method implies.
    """
    if idempotent is None:
        idempotent = request.method in _IDEMPOTENT_METHODS
    what = f"{request.method} {request.url.path}"
    for attempt in range(retry.attempts):
        last = attempt == retry.attempts - 1
        retry_after = None
        try:
            response = await http.send(request)
        except (httpx2.ConnectError, httpx2.ConnectTimeout) as exc:
            # The request never reached the SOAR, so it is safe to send again.
            if last:
                raise DriverError(f"Could not reach {product}: {exc}", retryable=True) from exc
        except httpx2.TimeoutException as exc:
            if last or not idempotent:
                raise DriverError(f"{product} request timed out: {what}", retryable=True) from exc
        except httpx2.TransportError as exc:
            if last or not idempotent:
                raise DriverError(f"Could not reach {product}: {exc}", retryable=True) from exc
        else:
            status = response.status_code
            if last or not (status == 429 or (idempotent and status in _RETRY_STATUSES)):
                return response
            retry_after = _retry_after(response)
            await response.aclose()
        wait = retry.delay(attempt, retry_after)
        if wait is None:
            return response  # the SOAR wants a longer wait than we are willing to give
        await retry.sleep(wait)
    raise AssertionError("unreachable")  # the last attempt always returns or raises


def _retry_after(response: httpx2.Response) -> float | None:
    """A ``Retry-After`` header in seconds. Dates are not supported and are ignored."""
    value = response.headers.get("Retry-After", "")
    try:
        seconds = float(value)
    except ValueError:
        return None
    return max(seconds, 0.0)
