"""SOAR drivers. Each driver lives in its own subpackage, e.g. :mod:`anysoar.drivers.mock`.

:class:`SwitchableDriver` switches between several drivers at runtime. :class:`Retry` sets
how the HTTP drivers retry failed requests.
"""

from anysoar.drivers.retry import Retry
from anysoar.drivers.switch import SoarSwitch, SwitchableDriver

__all__ = ["Retry", "SoarSwitch", "SwitchableDriver"]
