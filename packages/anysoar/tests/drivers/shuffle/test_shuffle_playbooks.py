import json
import os
import uuid
from collections.abc import AsyncIterator

import httpx2
import pytest
import pytest_asyncio

from anysoar.drivers.shuffle import ShuffleDriver
from anysoar.drivers.shuffle.client import ShuffleAPIError
from anysoar.drivers.shuffle.incidents import CATEGORY
from anysoar.errors import DriverError, NotFoundError
from anysoar.interface import ActionTier, Capability, PlaybookRunStatus
from anysoar.testing import DriverContract

from .fake_shuffle import API_KEY, BASE_URL, FakeShuffle, new_incident


@pytest.fixture
def shuffle() -> FakeShuffle:
    return FakeShuffle()


@pytest.fixture
def soar(shuffle: FakeShuffle) -> ShuffleDriver:
    return ShuffleDriver(BASE_URL, API_KEY, transport=shuffle.transport())


class TestShuffleContract(DriverContract):
    @pytest.fixture
    def fake(self) -> FakeShuffle:
        return FakeShuffle()

    @pytest.fixture
    def driver(self, fake: FakeShuffle) -> ShuffleDriver:
        return ShuffleDriver(BASE_URL, API_KEY, transport=fake.transport())

    @pytest.fixture
    def case_uid(self, fake: FakeShuffle) -> str:
        return fake.open_incident


class TestConfiguration:
    async def test_capabilities(self, soar: ShuffleDriver) -> None:
        info = await soar.describe()
        assert info.name == "shuffle"
        assert info.soar_product == "Shuffle"
        assert info.capabilities == {
            Capability.GET_CASE,
            Capability.ADD_NOTE,
            Capability.CLOSE_CASE,
            Capability.LIST_PLAYBOOKS,
            Capability.RUN_PLAYBOOK,
            Capability.GET_PLAYBOOK_RUN,
        }

    def test_reads_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHUFFLE_URL", BASE_URL)
        monkeypatch.setenv("SHUFFLE_API_KEY", API_KEY)
        ShuffleDriver()

    def test_needs_url_and_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHUFFLE_URL", raising=False)
        monkeypatch.delenv("SHUFFLE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="SHUFFLE_URL"):
            ShuffleDriver()


class TestPlaybooks:
    async def test_list(self, soar: ShuffleDriver, shuffle: FakeShuffle) -> None:
        playbooks = {p.name: p for p in await soar.list_playbooks()}
        assert set(playbooks) == {"Block sender", "Disable user account", "Block URL"}
        assert playbooks["Block sender"].tier is ActionTier.WRITE
        assert playbooks["Block sender"].description == "Block a sender at the mail gateway"
        assert playbooks["Disable user account"].tier is ActionTier.DESTRUCTIVE
        assert playbooks["Block URL"].input_schema == {
            "type": "object",
            "properties": {"url": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["url"],
        }
        (request,) = shuffle.requests
        assert request.url.params["truncate"] == "false"

    async def test_run_and_poll(self, soar: ShuffleDriver, shuffle: FakeShuffle) -> None:
        block = shuffle.by_name("Block sender")
        run = await soar.run_playbook(
            block["id"], case_uid="case-1", inputs={"sender": "it-support@example.net"}
        )
        assert run.status is PlaybookRunStatus.QUEUED
        assert run.playbook_uid == block["id"]

        sent = json.loads(shuffle.requests[-1].content)
        assert json.loads(sent["execution_argument"]) == {
            "sender": "it-support@example.net",
            "anysoar": {"case_uid": "case-1"},
        }

        running = await soar.get_playbook_run(run.uid)
        assert running.status is PlaybookRunStatus.RUNNING
        assert running.outputs == {}
        done = await soar.get_playbook_run(run.uid)
        assert done.status is PlaybookRunStatus.SUCCEEDED
        assert done.playbook_uid == block["id"]
        assert done.ended_time is not None and done.started_time is not None
        assert done.ended_time - done.started_time == 5000
        assert done.outputs == {
            "result": {"sender": "it-support@example.net", "anysoar": {"case_uid": "case-1"}}
        }

    async def test_no_context_means_no_anysoar_key(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        await soar.run_playbook(shuffle.by_name("Block sender")["id"])
        sent = json.loads(shuffle.requests[-1].content)
        assert sent["execution_argument"] == "{}"

    async def test_run_token_never_leaves_the_driver(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        run = await soar.run_playbook(shuffle.by_name("Block sender")["id"])
        token = shuffle.executions[run.uid].authorization
        polled = await soar.get_playbook_run(run.uid)
        assert token not in run.model_dump_json()
        assert token not in polled.model_dump_json()
        assert "authorization" not in json.loads(shuffle.requests[-1].content)

    async def test_failed_step_fails_the_run(
        self, soar: ShuffleDriver, shuffle: FakeShuffle
    ) -> None:
        block = shuffle.by_name("Block sender")
        shuffle.failing_workflows.add(block["id"])
        run = await soar.run_playbook(block["id"])
        await soar.get_playbook_run(run.uid)
        done = await soar.get_playbook_run(run.uid)
        assert done.status is PlaybookRunStatus.FAILED
        assert done.message == "failed steps: echo"

    async def test_unknown_playbook_and_run(self, soar: ShuffleDriver) -> None:
        with pytest.raises(NotFoundError, match="playbook 'nope' not found"):
            await soar.run_playbook("nope")  # not a UUID: Shuffle says "not valid"
        missing = "00000000-0000-0000-0000-000000000000"
        with pytest.raises(NotFoundError):
            await soar.run_playbook(missing)  # a UUID: Shuffle says "doesn't exist"
        with pytest.raises(NotFoundError, match="playbook run 'nope' not found"):
            await soar.get_playbook_run("nope")


class TestErrors:
    async def test_bad_api_key(self, shuffle: FakeShuffle) -> None:
        soar = ShuffleDriver(BASE_URL, "wrong-key", transport=shuffle.transport())
        with pytest.raises(ShuffleAPIError) as raised:
            await soar.list_playbooks()
        assert raised.value.status == 401
        assert not raised.value.is_not_found
        assert not raised.value.retryable

    async def test_server_errors_are_retryable(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(503, text="upstream unavailable")

        soar = ShuffleDriver(BASE_URL, API_KEY, transport=httpx2.MockTransport(handler))
        with pytest.raises(ShuffleAPIError) as raised:
            await soar.list_playbooks()
        assert raised.value.retryable

    async def test_connection_errors_become_driver_errors(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        soar = ShuffleDriver(BASE_URL, API_KEY, transport=httpx2.MockTransport(handler))
        with pytest.raises(DriverError, match="Could not reach Shuffle") as raised:
            await soar.list_playbooks()
        assert raised.value.retryable

    async def test_success_false_with_200_is_an_error(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, json={"success": False, "reason": "Read only user"})

        soar = ShuffleDriver(BASE_URL, API_KEY, transport=httpx2.MockTransport(handler))
        with pytest.raises(ShuffleAPIError, match="Read only user"):
            await soar.list_playbooks()


live = pytest.mark.skipif(
    os.environ.get("ANYSOAR_LIVE_SHUFFLE") != "1",
    reason="needs a running Shuffle (demo/shuffle); set ANYSOAR_LIVE_SHUFFLE=1, "
    "SHUFFLE_URL and SHUFFLE_API_KEY",
)


@live
class TestLiveShuffleContract(DriverContract):
    """The contract suite against a real Shuffle. Runs workflows there."""

    playbook_poll_interval = 2.0
    playbook_max_polls = 60

    @pytest.fixture
    def driver(self) -> ShuffleDriver:
        return ShuffleDriver()

    @pytest_asyncio.fixture
    async def case_uid(self, driver: ShuffleDriver) -> AsyncIterator[str]:
        """A synthetic incident created for the test and deleted afterwards."""
        uid = str(uuid.uuid4())
        await driver._save_incident(new_incident(uid))
        yield uid
        org = await driver._org_id()
        await driver._client.request(
            "POST",  # not DELETE, despite Shuffle's integration guide
            f"/api/v1/orgs/{org}/delete_cache",
            json={"key": uid, "category": CATEGORY, "org_id": org},  # org_id is required
        )
