"""How HTTP drivers retry failed requests.

A request is retried only when trying again cannot do the same thing twice:

- any request the SOAR did not process: a rate limit (429) or a connection that failed
  before the request was sent;
- an idempotent request (GET, HEAD, OPTIONS, PUT, DELETE, or one the driver marks
  idempotent, such as a search sent as POST) also after a server error (500, 502, 503, 504)
  or a timeout, when the SOAR may or may not have acted on it.

Waits grow exponentially with jitter, and follow a ``Retry-After`` header in seconds when
the SOAR sends one (up to ``max_delay``). Writes that may have happened are never repeated;
their errors reach the caller marked ``retryable``, to decide for itself.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

__all__ = ["Retry"]


@dataclass(frozen=True)
class Retry:
    """How a driver retries requests. ``Retry(attempts=1)`` turns retrying off."""

    attempts: int = 3
    """Tries in all, the first included."""
    base_delay: float = 0.5
    """Seconds before the first retry; each later wait doubles, with jitter."""
    max_delay: float = 10.0
    """The longest wait, also for ``Retry-After``. A longer ``Retry-After`` is not waited
    for: the error is returned instead."""
    sleep: Callable[[float], Awaitable[None]] = field(default=asyncio.sleep, compare=False)
    """How to wait; tests replace it."""

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts must be at least 1")

    def delay(self, retry: int, retry_after: float | None = None) -> float | None:
        """Seconds to wait before retry number ``retry`` (0 for the first), or None if the
        SOAR asks for a longer wait than ``max_delay``."""
        if retry_after is not None:
            return retry_after if retry_after <= self.max_delay else None
        return min(self.max_delay, self.base_delay * 2.0**retry) * random.uniform(0.5, 1.0)
