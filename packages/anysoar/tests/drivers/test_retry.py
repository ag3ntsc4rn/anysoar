import httpx2
import pytest

from anysoar.drivers import Retry
from anysoar.drivers._http import send
from anysoar.errors import DriverError

URL = "http://soar.test/api/thing"


class Recorder:
    """A transport that answers from a script, one step per request, and records them.

    A step is an HTTP status, or an exception class to raise instead of answering."""

    def __init__(self, *steps: int | type[Exception], headers: dict[str, str] | None = None):
        self.steps = list(steps)
        self.headers = headers or {}
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        step = self.steps.pop(0)
        if isinstance(step, type):
            raise step("scripted failure", request=request)  # type: ignore[call-arg]
        return httpx2.Response(step, headers=self.headers, json={})


def retry(waits: list[float], **kwargs: float) -> Retry:
    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    return Retry(sleep=sleep, **kwargs)  # type: ignore[arg-type]


async def run(
    recorder: Recorder,
    method: str = "GET",
    *,
    policy: Retry | None = None,
    idempotent: bool | None = None,
) -> httpx2.Response:
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(recorder)) as http:
        request = http.build_request(method, URL, json={} if method != "GET" else None)
        return await send(
            http, request, product="SOAR", retry=policy or retry([]), idempotent=idempotent
        )


class TestWhatIsRetried:
    async def test_reads_after_server_errors(self) -> None:
        recorder = Recorder(503, 502, 200)
        assert (await run(recorder)).status_code == 200
        assert len(recorder.requests) == 3

    async def test_gives_up_after_the_last_attempt(self) -> None:
        recorder = Recorder(503, 503, 503)
        assert (await run(recorder)).status_code == 503  # for the client to turn into an error
        assert len(recorder.requests) == 3

    async def test_writes_are_not_repeated_after_server_errors(self) -> None:
        recorder = Recorder(502, 200)
        assert (await run(recorder, "POST")).status_code == 502
        assert len(recorder.requests) == 1

    @pytest.mark.parametrize("method", ["GET", "POST", "PATCH"])
    async def test_rate_limits_are_retried_for_any_request(self, method: str) -> None:
        recorder = Recorder(429, 201)
        assert (await run(recorder, method)).status_code == 201
        assert len(recorder.requests) == 2

    async def test_writes_marked_idempotent(self) -> None:
        recorder = Recorder(500, 200)
        assert (await run(recorder, "POST", idempotent=True)).status_code == 200

    async def test_client_errors_are_not_retried(self) -> None:
        recorder = Recorder(404)
        assert (await run(recorder)).status_code == 404
        assert len(recorder.requests) == 1

    @pytest.mark.parametrize("method", ["GET", "POST"])
    async def test_failed_connections_for_any_request(self, method: str) -> None:
        recorder = Recorder(httpx2.ConnectError, httpx2.ConnectTimeout, 200)
        assert (await run(recorder, method)).status_code == 200

    async def test_failed_connections_end_in_a_retryable_error(self) -> None:
        recorder = Recorder(httpx2.ConnectError, httpx2.ConnectError, httpx2.ConnectError)
        with pytest.raises(DriverError, match="Could not reach SOAR") as error:
            await run(recorder)
        assert error.value.retryable
        assert len(recorder.requests) == 3

    async def test_timeouts_retry_reads(self) -> None:
        recorder = Recorder(httpx2.ReadTimeout, 200)
        assert (await run(recorder)).status_code == 200

    async def test_timeouts_do_not_repeat_writes(self) -> None:
        recorder = Recorder(httpx2.ReadTimeout, 200)
        with pytest.raises(DriverError, match="timed out: POST /api/thing") as error:
            await run(recorder, "POST")
        assert error.value.retryable  # the caller may decide to try again
        assert len(recorder.requests) == 1

    async def test_one_attempt_turns_retrying_off(self) -> None:
        recorder = Recorder(503, 200)
        assert (await run(recorder, policy=retry([], attempts=1))).status_code == 503


class TestWaiting:
    async def test_backs_off_exponentially_with_jitter(self) -> None:
        waits: list[float] = []
        await run(Recorder(503, 503, 200), policy=retry(waits, base_delay=1.0))
        assert len(waits) == 2
        assert 0.5 <= waits[0] <= 1.0
        assert 1.0 <= waits[1] <= 2.0

    async def test_follows_retry_after(self) -> None:
        waits: list[float] = []
        await run(Recorder(429, 200, headers={"Retry-After": "3"}), policy=retry(waits))
        assert waits == [3.0]

    async def test_will_not_wait_longer_than_max_delay(self) -> None:
        waits: list[float] = []
        recorder = Recorder(429, 200, headers={"Retry-After": "120"})
        response = await run(recorder, policy=retry(waits, max_delay=10))
        assert response.status_code == 429
        assert waits == []
        assert len(recorder.requests) == 1

    @pytest.mark.parametrize(("attempt", "cap"), [(0, 0.5), (1, 1.0), (2, 2.0), (10, 10.0)])
    def test_delay_is_capped(self, attempt: int, cap: float) -> None:
        delay = Retry().delay(attempt)
        assert delay is not None
        assert cap / 2 <= delay <= cap

    def test_needs_an_attempt(self) -> None:
        with pytest.raises(ValueError, match="attempts"):
            Retry(attempts=0)
