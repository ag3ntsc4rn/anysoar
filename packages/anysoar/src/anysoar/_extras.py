"""Clear errors for optional dependencies that are not installed."""

from __future__ import annotations

__all__ = ["missing_extra"]


def missing_extra(extra: str, error: ModuleNotFoundError) -> ModuleNotFoundError:
    """An error telling the user which anysoar extra provides the missing module."""
    return ModuleNotFoundError(
        f"{error.name!r} is not installed; it comes with the {extra!r} extra: "
        f'pip install "anysoar[{extra}]"',
        name=error.name,
    )
