"""Driver for the Shuffle SOAR (https://shuffler.io). Needs the ``shuffle`` extra.

    from anysoar.drivers.shuffle import ShuffleDriver

    async with ShuffleDriver("http://127.0.0.1:5001", api_key) as soar:
        playbooks = await soar.list_playbooks()

A local Shuffle for development lives in ``demo/shuffle`` in the repository.
"""

from anysoar.drivers.shuffle.driver import DESTRUCTIVE_TAG, ShuffleDriver

__all__ = ["DESTRUCTIVE_TAG", "ShuffleDriver"]
