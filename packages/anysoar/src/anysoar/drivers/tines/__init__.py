"""Driver for the Tines SOAR (https://www.tines.com). Needs the ``tines`` extra.

    from anysoar.drivers.tines import TinesDriver

    async with TinesDriver("https://example-tenant.tines.com", api_key) as soar:
        cases = await soar.list_cases()

A free Tines Community Edition tenant is enough to try it.
"""

from anysoar.drivers.tines.driver import DESTRUCTIVE_TAG, TinesDriver

__all__ = ["DESTRUCTIVE_TAG", "TinesDriver"]
