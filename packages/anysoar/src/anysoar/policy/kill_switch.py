"""The kill switch: stops all SOAR operations at once."""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["KillSwitch"]

_REASON_LIMIT = 500


class KillSwitch:
    """While engaged, the policy layer denies every operation, reads included.

    It can be engaged in two ways:

    - in process, with :meth:`engage` (e.g. from a console), undone with :meth:`release`;
    - by creating the file at ``path``, e.g. ``touch ~/.local/state/anysoar/STOP``. This works
      from any shell without the agent's cooperation. The first line of the file, if any, is
      used as the reason. Delete the file to release it; :meth:`release` does not.

    The switch is checked when each call arrives and again after any approval. Calls already
    running in the SOAR are not interrupted.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._reason: str | None = None

    def engage(self, reason: str = "engaged by operator") -> None:
        self._reason = reason

    def release(self) -> None:
        """Release the in-process switch. A kill switch file must be deleted separately."""
        self._reason = None

    @property
    def engaged(self) -> bool:
        return self.reason is not None

    @property
    def reason(self) -> str | None:
        """Why the switch is engaged, or ``None`` if it is not."""
        if self._reason is not None:
            return self._reason
        if self.path is None:
            return None
        try:
            with self.path.open(encoding="utf-8", errors="replace") as file:
                first_line = file.readline(_REASON_LIMIT).strip()
        except FileNotFoundError:
            return None
        except OSError as exc:
            # Exists but unreadable (e.g. a directory or no permission): fail closed.
            return f"kill switch file {self.path} present ({exc.strerror})"
        return first_line or f"kill switch file {self.path} present"
