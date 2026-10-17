"""SOAR drivers. Each driver lives in its own subpackage, e.g. :mod:`anysoar.drivers.mock`.

:class:`SwitchableDriver` switches between several drivers at runtime. :class:`Retry` sets
how the HTTP drivers retry failed requests. :func:`available_drivers` and
:func:`create_driver` find drivers by name, including drivers other packages provide (see
:mod:`anysoar.drivers.registry`).
"""

from anysoar.drivers.registry import (
    ENTRY_POINT_GROUP,
    DriverSpec,
    available_drivers,
    create_driver,
)
from anysoar.drivers.retry import Retry
from anysoar.drivers.switch import SoarSwitch, SwitchableDriver

__all__ = [
    "ENTRY_POINT_GROUP",
    "DriverSpec",
    "Retry",
    "SoarSwitch",
    "SwitchableDriver",
    "available_drivers",
    "create_driver",
]
