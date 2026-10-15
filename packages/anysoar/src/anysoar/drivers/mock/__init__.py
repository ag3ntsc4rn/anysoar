"""An in-memory fake SOAR for development, demos and tests.

The mock driver implements every capability against a synthetic phishing scenario, with no
network access or external dependencies::

    from anysoar.drivers.mock import MockDriver

    async with MockDriver() as soar:
        page = await soar.list_alerts()
"""

from anysoar.drivers.mock.driver import MockDriver

__all__ = ["MockDriver"]
