import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx2
import pytest
import pytest_asyncio

from anysoar.drivers.tines import TinesDriver
from anysoar.drivers.tines.client import TinesAPIError
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import ActionTier, Capability, PlaybookRunStatus
from anysoar.testing import DriverContract

from .fake_tines import API_KEY, BASE_URL, WEBHOOK_SECRET, FakeTines


@pytest.fixture
def tines() -> FakeTines:
    return FakeTines()


@pytest.fixture
def soar(tines: FakeTines) -> TinesDriver:
    return TinesDriver(BASE_URL, API_KEY, transport=tines.transport())


class TestTinesContract(DriverContract):
    @pytest.fixture
    def fake(self) -> FakeTines:
        return FakeTines()

    @pytest.fixture
    def driver(self, fake: FakeTines) -> TinesDriver:
        return TinesDriver(BASE_URL, API_KEY, transport=fake.transport())

    @pytest.fixture
    def case_uid(self, fake: FakeTines) -> str:
        return str(fake.open_case)


class TestConfiguration:
    async def test_capabilities(self, soar: TinesDriver) -> None:
        info = await soar.describe()
        assert info.name == "tines"
        assert info.soar_product == "Tines"
        assert info.capabilities == {
            Capability.LIST_CASES,
            Capability.GET_CASE,
            Capability.ADD_NOTE,
            Capability.CLOSE_CASE,
            Capability.LIST_PLAYBOOKS,
            Capability.RUN_PLAYBOOK,
            Capability.GET_PLAYBOOK_RUN,
        }

    def test_reads_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TINES_URL", BASE_URL)
        monkeypatch.setenv("TINES_API_KEY", API_KEY)
        monkeypatch.setenv("TINES_TEAM_ID", "276")
        assert TinesDriver()._team == "276"

    def test_needs_url_and_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TINES_URL", raising=False)
        monkeypatch.delenv("TINES_API_KEY", raising=False)
        with pytest.raises(ValueError, match="TINES_URL"):
            TinesDriver()

    def test_team_must_be_an_id(self) -> None:
        with pytest.raises(ValueError, match="team_id"):
            TinesDriver(BASE_URL, API_KEY, team_id="SOC")


class TestPlaybooks:
    async def test_list(self, soar: TinesDriver, tines: FakeTines) -> None:
        playbooks = {p.name: p for p in await soar.list_playbooks()}
        # Stories without Send to Story, or disabled, cannot be run.
        assert set(playbooks) == {"Block sender", "Disable user account", "Look up sender"}
        assert playbooks["Block sender"].uid == str(tines.block_sender)
        assert playbooks["Block sender"].tier is ActionTier.WRITE
        assert playbooks["Block sender"].description == "Block a sender at the gateway"
        assert playbooks["Disable user account"].tier is ActionTier.DESTRUCTIVE
        assert tines.requests[-1].url.params["filter"] == "SEND_TO_STORY_ENABLED"

    async def test_run_and_poll(self, soar: TinesDriver, tines: FakeTines) -> None:
        uid = str(tines.block_sender)
        run = await soar.run_playbook(
            uid, case_uid="42", inputs={"sender": "it-support@example.net"}
        )
        assert run.status is PlaybookRunStatus.QUEUED
        assert run.playbook_uid == uid

        webhook = tines.requests[-1]
        assert webhook.url.path.endswith(f"/{WEBHOOK_SECRET}")
        assert "Authorization" not in webhook.headers  # the secret authenticates it
        sent = json.loads(webhook.content)
        token = sent["anysoar"].pop("run_uid")
        assert run.uid == f"{uid}:{token}"
        assert sent == {"sender": "it-support@example.net", "anysoar": {"case_uid": "42"}}

        running = await soar.get_playbook_run(run.uid)
        assert running.status is PlaybookRunStatus.RUNNING
        assert running.started_time is not None
        assert running.outputs == {}
        done = await soar.get_playbook_run(run.uid)
        assert done.status is PlaybookRunStatus.SUCCEEDED
        assert (done.uid, done.playbook_uid) == (run.uid, uid)
        assert done.ended_time is not None and done.started_time is not None
        assert done.ended_time - done.started_time == 1000
        # The exit action's own output, without the upstream webhook payload.
        assert done.outputs == {
            "result": {"exit": {"blocked": True, "sender": "it-support@example.net"}}
        }

    async def test_run_not_yet_received_is_queued(
        self, soar: TinesDriver, tines: FakeTines
    ) -> None:
        run = await soar.run_playbook(str(tines.block_sender))
        tines.runs.clear()  # Tines has not turned the webhook call into an event yet
        assert (await soar.get_playbook_run(run.uid)).status is PlaybookRunStatus.QUEUED

    async def test_runs_are_told_apart(self, soar: TinesDriver, tines: FakeTines) -> None:
        first = await soar.run_playbook(str(tines.block_sender), inputs={"sender": "a@example.net"})
        await soar.run_playbook(str(tines.block_sender), inputs={"sender": "b@example.net"})
        for _ in range(3):
            polled = await soar.get_playbook_run(first.uid)
        assert polled.outputs == {"result": {"exit": {"blocked": True, "sender": "a@example.net"}}}

    async def test_webhook_without_secret_uses_the_api_key(
        self, soar: TinesDriver, tines: FakeTines
    ) -> None:
        await soar.run_playbook(str(tines.public_lookup))
        webhook = tines.requests[-1]
        assert webhook.url.path.count("/") == 2  # /webhook/<path>
        assert webhook.headers["Authorization"] == f"Bearer {API_KEY}"

    async def test_timeout_fails_the_run(self, soar: TinesDriver, tines: FakeTines) -> None:
        tines.stalled_stories.add(tines.block_sender)
        run = await soar.run_playbook(str(tines.block_sender))
        polled = await soar.get_playbook_run(run.uid)
        assert polled.status is PlaybookRunStatus.RUNNING
        tines.runs[-1].created = datetime.now(UTC) - timedelta(seconds=121)
        polled = await soar.get_playbook_run(run.uid)
        assert polled.status is PlaybookRunStatus.FAILED
        assert polled.message == "no exit action reached within the story's 120s timeout"

    async def test_stories_that_cannot_run(self, soar: TinesDriver, tines: FakeTines) -> None:
        not_shared = next(s for s in tines.stories.values() if s["name"] == "Not shared")
        with pytest.raises(DriverError, match="enable Send to Story"):
            await soar.run_playbook(str(not_shared["id"]))
        retired = next(s for s in tines.stories.values() if s["name"] == "Retired")
        with pytest.raises(DriverError, match="disabled"):
            await soar.run_playbook(str(retired["id"]))

    async def test_unknown_playbook_and_run(self, soar: TinesDriver, tines: FakeTines) -> None:
        for uid in ("nope", "999999"):
            with pytest.raises(NotFoundError, match=f"playbook '{uid}' not found"):
                await soar.run_playbook(uid)
        for run_uid in ("nope", f"{tines.block_sender}:short", f"999999:{'0' * 32}"):
            with pytest.raises(NotFoundError, match="playbook run"):
                await soar.get_playbook_run(run_uid)

    async def test_other_teams_stories_are_hidden(self, tines: FakeTines) -> None:
        soar = TinesDriver(BASE_URL, API_KEY, team_id=1, transport=tines.transport())
        with pytest.raises(NotFoundError):
            await soar.run_playbook(str(tines.block_sender))


class TestErrors:
    async def test_bad_api_key(self, tines: FakeTines) -> None:
        soar = TinesDriver(BASE_URL, "wrong-key", transport=tines.transport())
        with pytest.raises(TinesAPIError, match="Unauthorized") as raised:
            await soar.list_playbooks()
        assert raised.value.status == 401
        assert not raised.value.is_not_found
        assert not raised.value.retryable

    @pytest.mark.parametrize("status", [429, 503])
    async def test_retryable(self, status: int) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(status, text="slow down")

        soar = TinesDriver(BASE_URL, API_KEY, transport=httpx2.MockTransport(handler))
        with pytest.raises(TinesAPIError) as raised:
            await soar.list_playbooks()
        assert raised.value.retryable

    async def test_error_lists(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(422, json={"errors": ["Closure conditions not met"]})

        soar = TinesDriver(BASE_URL, API_KEY, transport=httpx2.MockTransport(handler))
        with pytest.raises(TinesAPIError, match="Closure conditions not met"):
            await soar.list_cases()

    async def test_connection_errors_become_driver_errors(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        soar = TinesDriver(BASE_URL, API_KEY, transport=httpx2.MockTransport(handler))
        with pytest.raises(DriverError, match="Could not reach Tines") as raised:
            await soar.list_playbooks()
        assert raised.value.retryable


live = pytest.mark.skipif(
    os.environ.get("ANYSOAR_LIVE_TINES") != "1",
    reason="needs a Tines tenant; set ANYSOAR_LIVE_TINES=1, TINES_URL, TINES_API_KEY and "
    "TINES_TEAM_ID",
)


@live
class TestLiveTinesContract(DriverContract):
    """The contract suite against a real Tines tenant. Runs Send to Story stories there."""

    playbook_poll_interval = 2.0
    playbook_max_polls = 60

    @pytest.fixture
    def driver(self) -> TinesDriver:
        return TinesDriver()

    @pytest_asyncio.fixture
    async def case_uid(self, driver: TinesDriver) -> AsyncIterator[str]:
        """A synthetic case created for the test and deleted afterwards."""
        case = await driver._client.request(
            "POST",
            "/api/v2/cases",
            json={
                "team_id": int(os.environ["TINES_TEAM_ID"]),
                "name": "anysoar contract test (synthetic)",
                "description": "Created and deleted by anysoar's live contract tests.",
                "priority": "low",
            },
        )
        uid = str(case["case_id"])
        yield uid
        await driver._client.request("DELETE", f"/api/v2/cases/{uid}")
