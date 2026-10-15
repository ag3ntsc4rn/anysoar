from importlib.metadata import version

import anysoar


def test_version_matches_distribution_metadata() -> None:
    assert anysoar.__version__ == version("anysoar")
