"""SOAR drivers. Each driver lives in its own subpackage, e.g. :mod:`anysoar.drivers.mock`.

:class:`SwitchableDriver` switches between several drivers at runtime.
"""

from anysoar.drivers.switch import SoarSwitch, SwitchableDriver

__all__ = ["SoarSwitch", "SwitchableDriver"]
