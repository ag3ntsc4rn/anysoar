"""Driver for TheHive 5 (https://strangebee.com/thehive/). Needs the ``thehive`` extra.

    from anysoar.drivers.thehive import TheHiveDriver

    async with TheHiveDriver("http://127.0.0.1:9000", api_key) as soar:
        alerts = await soar.list_alerts()

``demo/thehive`` in anysoar's repository runs TheHive locally in Docker.
"""

from anysoar.drivers.thehive.driver import TheHiveDriver

__all__ = ["TheHiveDriver"]
