import argparse
import logging
import sys
import types
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

from anysoar.drivers import ENTRY_POINT_GROUP, available_drivers, create_driver, registry
from anysoar.drivers.mock import MockDriver
from anysoar.interface import Driver
from anysoar.mcp import cli


class AcmeDriver(MockDriver):
    """A driver another package would provide."""

    name = "acme"


@pytest.fixture
def acme_package(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """An importable module standing in for an installed anysoar-acme package."""
    module = types.ModuleType("anysoar_acme")
    module.AcmeDriver = AcmeDriver  # type: ignore[attr-defined]
    module.not_a_driver = lambda: object()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anysoar_acme", module)
    return module


def installed(monkeypatch: pytest.MonkeyPatch, *entries: tuple[str, str]) -> None:
    """Pretend packages declare these (name, target) entry points."""
    points = [EntryPoint(name, value, ENTRY_POINT_GROUP) for name, value in entries]

    def entry_points(*, group: str) -> list[EntryPoint]:
        assert group == ENTRY_POINT_GROUP
        return points

    monkeypatch.setattr(registry, "entry_points", entry_points)


class TestAvailableDrivers:
    def test_anysoars_own(self, monkeypatch: pytest.MonkeyPatch) -> None:
        installed(monkeypatch)
        drivers = available_drivers()
        assert list(drivers) == ["mock", "shuffle", "thehive", "tines"]
        assert all(d.built_in for d in drivers.values())
        assert drivers["thehive"].target == "anysoar.drivers.thehive:TheHiveDriver"

    def test_installed_packages_add_drivers(
        self, monkeypatch: pytest.MonkeyPatch, acme_package: types.ModuleType
    ) -> None:
        installed(monkeypatch, ("acme", "anysoar_acme:AcmeDriver"))
        drivers = available_drivers()
        assert list(drivers) == ["acme", "mock", "shuffle", "thehive", "tines"]
        assert not drivers["acme"].built_in
        assert drivers["acme"].provider == "an installed package"  # no metadata in this test

    def test_packages_cannot_replace_anysoars_own(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        installed(monkeypatch, ("thehive", "anysoar_acme:AcmeDriver"))
        with caplog.at_level(logging.WARNING):
            spec = available_drivers()["thehive"]
        assert spec.built_in
        assert spec.target == "anysoar.drivers.thehive:TheHiveDriver"
        assert "one of anysoar's own drivers" in caplog.text

    def test_first_package_wins_a_name(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        installed(
            monkeypatch,
            ("acme", "anysoar_acme:AcmeDriver"),
            ("acme", "elsewhere:OtherDriver"),
        )
        with caplog.at_level(logging.WARNING):
            assert available_drivers()["acme"].target == "anysoar_acme:AcmeDriver"
        assert "already provides it" in caplog.text


class TestCreateDriver:
    def test_creates_an_installed_driver(
        self, monkeypatch: pytest.MonkeyPatch, acme_package: types.ModuleType
    ) -> None:
        installed(monkeypatch, ("acme", "anysoar_acme:AcmeDriver"))
        driver = create_driver("acme")
        assert isinstance(driver, AcmeDriver)

    def test_creates_anysoars_own(self, monkeypatch: pytest.MonkeyPatch) -> None:
        installed(monkeypatch)
        assert isinstance(create_driver("mock"), MockDriver)

    def test_unknown_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        installed(monkeypatch)
        with pytest.raises(KeyError):
            create_driver("nope")

    def test_must_make_a_driver(
        self, monkeypatch: pytest.MonkeyPatch, acme_package: types.ModuleType
    ) -> None:
        installed(monkeypatch, ("acme", "anysoar_acme:not_a_driver"))
        with pytest.raises(TypeError, match="not a Driver"):
            create_driver("acme")

    def test_missing_module(self, monkeypatch: pytest.MonkeyPatch) -> None:
        installed(monkeypatch, ("ghost", "anysoar_ghost:GhostDriver"))
        with pytest.raises(ImportError):
            create_driver("ghost")


class TestAnysoarMcp:
    def args(self, tmp_path: Path, driver: str) -> argparse.Namespace:
        return argparse.Namespace(driver=driver, soar_switch=tmp_path / "SOAR")

    def test_serves_an_installed_driver(
        self, monkeypatch: pytest.MonkeyPatch, acme_package: types.ModuleType, tmp_path: Path
    ) -> None:
        installed(monkeypatch, ("acme", "anysoar_acme:AcmeDriver"))
        driver: Driver = cli._driver(self.args(tmp_path, "acme"))
        assert driver.name == "acme"

    def test_lists_installed_drivers_when_asked_for_an_unknown_one(
        self, monkeypatch: pytest.MonkeyPatch, acme_package: types.ModuleType, tmp_path: Path
    ) -> None:
        installed(monkeypatch, ("acme", "anysoar_acme:AcmeDriver"))
        with pytest.raises(SystemExit, match="from: acme, mock, shuffle, thehive, tines"):
            cli._driver(self.args(tmp_path, "nope"))

    def test_broken_driver_is_a_clear_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        installed(monkeypatch, ("ghost", "anysoar_ghost:GhostDriver"))
        with pytest.raises(SystemExit, match="cannot start the ghost driver"):
            cli._driver(self.args(tmp_path, "ghost"))
