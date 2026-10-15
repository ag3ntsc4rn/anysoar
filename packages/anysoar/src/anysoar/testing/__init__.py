"""Test utilities for driver authors. Needs the ``testing`` extra: ``pip install anysoar[testing]``.

:class:`DriverContract` is the contract test suite every driver must pass.
"""

from anysoar.testing.contract import DriverContract

__all__ = ["DriverContract"]
