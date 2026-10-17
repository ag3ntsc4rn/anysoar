"""Finding drivers by name: anysoar's own, and drivers other packages provide.

A package provides a driver by declaring an entry point in the ``anysoar.drivers`` group,
named after the driver, that points at the driver class (or any callable that takes no
arguments and returns a :class:`~anysoar.interface.Driver`)::

    # pyproject.toml of a package such as anysoar-acme
    [project.entry-points."anysoar.drivers"]
    acme = "anysoar_acme:AcmeDriver"

Once the package is installed, ``anysoar-mcp --driver acme`` starts it. The driver is
created with no arguments, so it reads its settings from the environment, as anysoar's own
drivers do (``SHUFFLE_URL``, ``TINES_API_KEY``...).

anysoar's own drivers keep their names: an installed package cannot replace one, since
that would change what an existing configuration talks to without anyone noticing.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points

from anysoar.interface import Driver

__all__ = ["ENTRY_POINT_GROUP", "DriverSpec", "available_drivers", "create_driver"]

ENTRY_POINT_GROUP = "anysoar.drivers"
"""The entry point group packages declare their drivers in."""

logger = logging.getLogger(__name__)

_BUILT_IN = {
    "mock": "anysoar.drivers.mock:MockDriver",
    "shuffle": "anysoar.drivers.shuffle:ShuffleDriver",
    "thehive": "anysoar.drivers.thehive:TheHiveDriver",
    "tines": "anysoar.drivers.tines:TinesDriver",
}


@dataclass(frozen=True)
class DriverSpec:
    """A driver that can be started by name."""

    name: str
    target: str
    """Where the driver is, as ``module:attribute``."""
    provider: str | None = None
    """The package that provides it, e.g. ``anysoar-acme 1.2.0``; None for anysoar's own."""

    @property
    def built_in(self) -> bool:
        return self.provider is None

    def load(self) -> Callable[[], Driver]:
        """Import the driver (class or factory). Raises ImportError if it cannot be loaded,
        e.g. because an extra is not installed."""
        module, _, attribute = self.target.partition(":")
        found = importlib.import_module(module)
        for part in attribute.split("."):
            found = getattr(found, part)
        if not callable(found):
            raise TypeError(f"driver {self.name!r} ({self.target}) is not callable")
        return found


def available_drivers() -> dict[str, DriverSpec]:
    """Every driver that can be started by name: anysoar's own and those installed packages
    provide, sorted by name. Nothing is imported."""
    specs = {name: DriverSpec(name, target) for name, target in _BUILT_IN.items()}
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        dist = getattr(entry, "dist", None)
        provider = f"{dist.name} {dist.version}" if dist is not None else "an installed package"
        if entry.name in _BUILT_IN:
            logger.warning(
                "ignoring the %r driver from %s: %r is one of anysoar's own drivers",
                entry.name,
                provider,
                entry.name,
            )
            continue
        if entry.name in specs:
            logger.warning(
                "ignoring the %r driver from %s: %s already provides it",
                entry.name,
                provider,
                specs[entry.name].provider,
            )
            continue
        specs[entry.name] = DriverSpec(entry.name, entry.value, provider)
    return dict(sorted(specs.items()))


def create_driver(name: str) -> Driver:
    """Start the driver called ``name`` with its settings from the environment.

    Raises KeyError for an unknown name, ImportError if it cannot be loaded, ValueError if
    its settings are missing (as anysoar's own drivers do), and TypeError if it does not
    make a :class:`~anysoar.interface.Driver`.
    """
    spec = available_drivers()[name]
    driver = spec.load()()
    if not isinstance(driver, Driver):
        raise TypeError(
            f"driver {name!r} ({spec.target}) made {type(driver).__name__}, not a Driver"
        )
    return driver
