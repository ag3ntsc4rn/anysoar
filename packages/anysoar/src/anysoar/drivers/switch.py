"""Switch the SOAR behind anysoar while agents keep running.

:class:`SwitchableDriver` holds several drivers and sends each call to whichever one a
:class:`SoarSwitch` names. The switch is a small file, like the kill switch, so another
process (an operator, or the console) can change it without talking to anysoar.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import JsonValue

from anysoar.interface import (
    AlertQuery,
    CaseQuery,
    Driver,
    DriverInfo,
    IndicatorEnrichment,
    Page,
    Playbook,
    PlaybookRun,
)
from anysoar.models import DetectionFinding, IncidentFinding, Note, Observable, VerdictId

__all__ = ["SoarSwitch", "SwitchableDriver"]

logger = logging.getLogger(__name__)


class SoarSwitch:
    """Names the active SOAR in a file. A missing or unknown name means ``default``."""

    def __init__(self, path: str | os.PathLike[str], choices: list[str], default: str) -> None:
        if default not in choices:
            raise ValueError(f"default {default!r} is not one of {choices}")
        self.path = Path(path)
        self.choices = list(choices)
        self.default = default

    @property
    def active(self) -> str:
        try:
            name = self.path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return self.default
        if name and name not in self.choices:
            logger.warning("%s names unknown SOAR %r; using %r", self.path, name, self.default)
        return name if name in self.choices else self.default

    def set(self, name: str) -> None:
        if name not in self.choices:
            raise ValueError(f"unknown SOAR {name!r}; choose from {self.choices}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(name + "\n", encoding="utf-8")
        tmp.replace(self.path)  # atomic, so readers never see a half-written name


class SwitchableDriver(Driver):
    """Sends each call to the driver the switch currently names.

    The driver is chosen when a call starts, so a call already in progress finishes on the
    SOAR it started on. :meth:`describe` reports the active driver, including its name and
    capabilities; calls it does not support raise
    :class:`~anysoar.errors.CapabilityNotSupportedError` from that driver.

    Args:
        drivers: The SOARs to switch between, by name. Closing this driver closes them all.
        switch: Names the active one.
    """

    name = "switchable"

    def __init__(self, drivers: Mapping[str, Driver], switch: SoarSwitch) -> None:
        if set(switch.choices) != set(drivers):
            raise ValueError("the switch's choices must be the drivers' names")
        self.drivers = dict(drivers)
        self.switch = switch
        self.name = switch.active  # type: ignore[misc]  # reports the active SOAR

    @property
    def active(self) -> Driver:
        name = self.switch.active
        if name != self.name:
            logger.info("SOAR switched from %r to %r", self.name, name)
            self.name = name  # type: ignore[misc]
        return self.drivers[name]

    async def describe(self) -> DriverInfo:
        return await self.active.describe()

    async def aclose(self) -> None:
        for driver in self.drivers.values():
            with contextlib.suppress(Exception):
                await driver.aclose()

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        return await self.active.list_alerts(query)

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        return await self.active.get_alert(alert_uid)

    async def list_cases(self, query: CaseQuery | None = None) -> Page[IncidentFinding]:
        return await self.active.list_cases(query)

    async def get_case(self, case_uid: str) -> IncidentFinding:
        return await self.active.get_case(case_uid)

    async def add_note(self, case_uid: str, note: Note) -> Note:
        return await self.active.add_note(case_uid, note)

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        return await self.active.close_case(case_uid, verdict_id=verdict_id, comment=comment)

    async def enrich_indicator(self, indicator: Observable) -> IndicatorEnrichment:
        return await self.active.enrich_indicator(indicator)

    async def list_playbooks(self) -> list[Playbook]:
        return await self.active.list_playbooks()

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        return await self.active.run_playbook(
            playbook_uid, case_uid=case_uid, alert_uid=alert_uid, inputs=inputs
        )

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        return await self.active.get_playbook_run(run_uid)
