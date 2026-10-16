from anysoar.drivers import Retry

NO_WAIT = Retry(base_delay=0)
"""Retries as drivers do them, without waiting, for drivers backed by fakes."""
