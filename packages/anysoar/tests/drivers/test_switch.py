import asyncio
import logging
from pathlib import Path

import pytest
from mcp import Client

from anysoar.drivers import SoarSwitch, SwitchableDriver
from anysoar.drivers.mock import MockDriver
from anysoar.drivers.shuffle import ShuffleDriver
from anysoar.errors import CapabilityNotSupportedError
from anysoar.interface import Capability, DriverInfo
from anysoar.mcp import create_server
from anysoar.mcp.cli import main
from anysoar.models import Note
from anysoar.policy import Action, Approval, GuardedDriver, MemoryAuditLog
from anysoar.testing import DriverContract

from .shuffle.fake_shuffle import API_KEY, BASE_URL, FakeShuffle


def switchable(tmp_path: Path, shuffle: FakeShuffle | None = None) -> SwitchableDriver:
    switch = SoarSwitch(tmp_path / "SOAR", ["mock", "shuffle"], default="mock")
    fake = shuffle or FakeShuffle()
    return SwitchableDriver(
        {
            "mock": MockDriver(),
            "shuffle": ShuffleDriver(BASE_URL, API_KEY, transport=fake.transport()),
        },
        switch,
    )


class TestSoarSwitch:
    def test_defaults_until_set(self, tmp_path: Path) -> None:
        switch = SoarSwitch(tmp_path / "state" / "SOAR", ["mock", "shuffle"], default="mock")
        assert switch.active == "mock"
        switch.set("shuffle")
        assert switch.active == "shuffle"
        assert (tmp_path / "state" / "SOAR").read_text() == "shuffle\n"
        assert not (tmp_path / "state" / "SOAR.tmp").exists()

    def test_unknown_names(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        switch = SoarSwitch(tmp_path / "SOAR", ["mock", "shuffle"], default="mock")
        (tmp_path / "SOAR").write_text("tines\n")
        with caplog.at_level(logging.WARNING):
            assert switch.active == "mock"
        assert "unknown SOAR 'tines'" in caplog.text
        with pytest.raises(ValueError, match="unknown SOAR"):
            switch.set("tines")
        with pytest.raises(ValueError, match="default"):
            SoarSwitch(tmp_path / "SOAR", ["mock"], default="shuffle")


class TestSwitchableDriver:
    async def test_follows_the_switch(self, tmp_path: Path) -> None:
        soar = switchable(tmp_path)
        info = await soar.describe()
        assert info.name == "mock"
        assert Capability.LIST_ALERTS in info.capabilities
        assert (await soar.get_case("case-0001")).metadata.uid == "case-0001"

        soar.switch.set("shuffle")
        info = await soar.describe()
        assert (info.name, info.soar_product) == ("shuffle", "Shuffle")
        assert Capability.LIST_ALERTS not in info.capabilities
        assert soar.name == "shuffle"
        with pytest.raises(CapabilityNotSupportedError) as raised:
            await soar.list_alerts()
        assert raised.value.driver == "shuffle"

    def test_needs_a_driver_per_choice(self, tmp_path: Path) -> None:
        switch = SoarSwitch(tmp_path / "SOAR", ["mock", "shuffle"], default="mock")
        with pytest.raises(ValueError, match="choices"):
            SwitchableDriver({"mock": MockDriver()}, switch)

    async def test_closes_every_driver(self, tmp_path: Path) -> None:
        closed: list[str] = []

        class Closing(MockDriver):
            def __init__(self, label: str) -> None:
                super().__init__()
                self.label = label

            async def aclose(self) -> None:
                closed.append(self.label)

        switch = SoarSwitch(tmp_path / "SOAR", ["a", "b"], default="a")
        async with SwitchableDriver({"a": Closing("a"), "b": Closing("b")}, switch):
            pass
        assert sorted(closed) == ["a", "b"]


class TestSwitchableContract(DriverContract):
    @pytest.fixture
    def driver(self, tmp_path: Path) -> SwitchableDriver:
        return switchable(tmp_path)

    @pytest.fixture
    def case_uid(self) -> str:
        return "case-0002"


class RecordingApprover:
    def __init__(self) -> None:
        self.asked: list[Action] = []

    async def request_approval(self, action: Action) -> Approval:
        self.asked.append(action)
        return Approval(approved=True, approver="test")


class TestGuardAfterASwitch:
    async def test_unsupported_calls_fail_before_approval(self, tmp_path: Path) -> None:
        approver = RecordingApprover()

        class NoNotes(MockDriver):
            async def add_note(self, case_uid: str, note: Note) -> Note:
                raise AssertionError("never called")

            async def describe(self) -> DriverInfo:
                info = await super().describe()
                return info.model_copy(
                    update={"capabilities": info.capabilities - {Capability.ADD_NOTE}}
                )

        switch = SoarSwitch(tmp_path / "SOAR", ["mock", "limited"], default="mock")
        guard = GuardedDriver(
            SwitchableDriver({"mock": MockDriver(), "limited": NoNotes()}, switch),
            approver=approver,
        )
        await guard.add_note("case-0002", Note(comment="on the mock"))
        switch.set("limited")
        with pytest.raises(CapabilityNotSupportedError) as raised:
            await guard.add_note("case-0002", Note(comment="on the limited SOAR"))
        assert raised.value.driver == "limited"  # named as the switch names it
        assert len(approver.asked) == 1

    async def test_audit_names_the_active_soar(self, tmp_path: Path) -> None:
        log = MemoryAuditLog()
        shuffle = FakeShuffle()
        soar = switchable(tmp_path, shuffle)
        guard = GuardedDriver(soar, audit_log=log)
        await guard.get_case("case-0001")
        soar.switch.set("shuffle")
        await guard.get_case(shuffle.open_incident)
        assert [e.driver for e in log.events] == ["mock", "mock", "shuffle", "shuffle"]


async def test_mcp_tools_follow_the_switch(tmp_path: Path) -> None:
    soar = switchable(tmp_path)
    server = await create_server(GuardedDriver(soar), resync_interval=0.05)
    async with Client(server) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"list_alerts", "enrich_indicator", "list_cases"} <= names

        soar.switch.set("shuffle")
        for _ in range(100):
            names = {t.name for t in (await client.list_tools()).tools}
            if "list_alerts" not in names:
                break
            await asyncio.sleep(0.02)
        assert "list_alerts" not in names
        assert "enrich_indicator" not in names
        assert {"list_cases", "get_case", "run_playbook", "describe_soar"} <= names
        described = await client.call_tool("describe_soar", {})
        assert described.structured_content is not None
        assert described.structured_content["driver"] == "shuffle"

        soar.switch.set("mock")
        for _ in range(100):
            if "list_alerts" in {t.name for t in (await client.list_tools()).tools}:
                break
            await asyncio.sleep(0.02)
        assert "list_alerts" in {t.name for t in (await client.list_tools()).tools}


@pytest.mark.parametrize("drivers", ["mock,nope", "mock,mock", ","])
def test_cli_rejects_bad_driver_lists(drivers: str) -> None:
    with pytest.raises(SystemExit, match="must name distinct drivers"):
        main(["--driver", drivers])
