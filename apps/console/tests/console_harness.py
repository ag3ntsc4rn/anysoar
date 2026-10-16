"""A real console server for tests, and clients for its two kinds of callers."""

from dataclasses import dataclass

import httpx2

from anysoar.policy import HttpApprover
from anysoar_console.app import CSRF_HEADER, SESSION_COOKIE, ConsoleConfig


@dataclass
class Console:
    url: str
    config: ConsoleConfig

    def approver(self) -> HttpApprover:
        return HttpApprover(self.url, self.config.submit_token, poll_wait=0.2)

    def submitter(self) -> httpx2.AsyncClient:
        token = self.config.submit_token
        return httpx2.AsyncClient(base_url=self.url, headers={"Authorization": f"Bearer {token}"})

    async def person(self) -> httpx2.AsyncClient:
        """A signed-in browser."""
        client = httpx2.AsyncClient(base_url=self.url, headers={CSRF_HEADER: "1"})
        response = await client.get(f"/login?token={self.config.login_token}")
        assert response.status_code in (200, 303)
        assert client.cookies.get(SESSION_COOKIE)
        return client
