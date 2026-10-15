"""The driver contract: what every SOAR driver implements and how it reports its capabilities.

A driver subclasses :class:`Driver` and overrides the methods for the operations its SOAR
supports. Each overridable method corresponds to one :class:`Capability`; the capabilities a
driver supports are exactly the methods it overrides, so they cannot drift apart. Calling an
operation a driver does not implement raises :class:`~anysoar.errors.CapabilityNotSupportedError`.

All methods are async. Data crossing the interface uses the OCSF-aligned models in
:mod:`anysoar.models`; the few concepts OCSF does not cover (playbooks, playbook runs, paging
and queries) are defined here.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType, TracebackType
from typing import ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from anysoar.errors import CapabilityNotSupportedError
from anysoar.models import (
    DetectionFinding,
    DetectionFindingStatusId,
    Enrichment,
    IncidentFinding,
    Note,
    Observable,
    SeverityId,
    Timestamp,
    VerdictId,
)

__all__ = [
    "CAPABILITY_TIERS",
    "ActionTier",
    "AlertQuery",
    "Capability",
    "Driver",
    "DriverInfo",
    "IndicatorEnrichment",
    "Page",
    "Playbook",
    "PlaybookRun",
    "PlaybookRunStatus",
]


class ActionTier(StrEnum):
    """How much risk an operation carries; the policy layer gates operations by tier."""

    READ = "read"
    """No change to the SOAR or the environment. Allowed freely."""
    WRITE = "write"
    """Changes SOAR state or the environment. Requires human approval."""
    DESTRUCTIVE = "destructive"
    """Irreversible or high-impact. Blocked."""


class Capability(StrEnum):
    """An operation a driver can support. Values match the :class:`Driver` method names."""

    LIST_ALERTS = "list_alerts"
    GET_ALERT = "get_alert"
    GET_CASE = "get_case"
    ADD_NOTE = "add_note"
    ENRICH_INDICATOR = "enrich_indicator"
    LIST_PLAYBOOKS = "list_playbooks"
    RUN_PLAYBOOK = "run_playbook"
    GET_PLAYBOOK_RUN = "get_playbook_run"
    CLOSE_CASE = "close_case"

    @property
    def tier(self) -> ActionTier:
        """The inherent tier of this operation (see :data:`CAPABILITY_TIERS`)."""
        return CAPABILITY_TIERS[self]


CAPABILITY_TIERS: Mapping[Capability, ActionTier] = MappingProxyType(
    {
        Capability.LIST_ALERTS: ActionTier.READ,
        Capability.GET_ALERT: ActionTier.READ,
        Capability.GET_CASE: ActionTier.READ,
        Capability.ADD_NOTE: ActionTier.WRITE,
        Capability.ENRICH_INDICATOR: ActionTier.READ,
        Capability.LIST_PLAYBOOKS: ActionTier.READ,
        # The minimum tier; a playbook may declare a higher one (see Playbook.tier).
        Capability.RUN_PLAYBOOK: ActionTier.WRITE,
        Capability.GET_PLAYBOOK_RUN: ActionTier.READ,
        Capability.CLOSE_CASE: ActionTier.WRITE,
    }
)
"""The inherent tier of each capability."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DriverInfo(_Model):
    """What a driver reports about itself and the SOAR behind it."""

    name: str
    """Driver name, e.g. ``"mock"`` or ``"shuffle"``."""
    capabilities: frozenset[Capability]
    driver_version: str | None = None
    soar_product: str | None = None
    soar_version: str | None = None


class Page[T](_Model):
    """One page of results. Pass ``next_cursor`` back to fetch the next page."""

    items: list[T]
    next_cursor: str | None = None


class AlertQuery(_Model):
    """Filters for :meth:`Driver.list_alerts`. Unset filters match everything."""

    status_ids: frozenset[DetectionFindingStatusId] | None = None
    min_severity_id: SeverityId | None = None
    since: Timestamp | None = None
    """Only alerts created at or after this time."""
    until: Timestamp | None = None
    """Only alerts created before this time."""
    limit: int = Field(default=50, ge=1, le=500)
    cursor: str | None = None


class IndicatorEnrichment(_Model):
    """Result of :meth:`Driver.enrich_indicator`."""

    observable: Observable
    """The enriched indicator, with ``reputation`` set when the SOAR provides one."""
    enrichments: list[Enrichment] = Field(default_factory=list)


class Playbook(_Model):
    """A playbook (workflow) the SOAR can run. OCSF has no equivalent concept."""

    uid: str
    name: str
    description: str | None = None
    tier: ActionTier = ActionTier.WRITE
    """Risk of running this playbook; never lower than ``WRITE``."""
    input_schema: dict[str, JsonValue] | None = None
    """JSON Schema for ``inputs`` accepted by :meth:`Driver.run_playbook`, if known."""

    @field_validator("tier")
    @classmethod
    def _at_least_write(cls, tier: ActionTier) -> ActionTier:
        if tier is ActionTier.READ:
            raise ValueError("a playbook's tier cannot be lower than write")
        return tier


class PlaybookRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"

    @property
    def is_finished(self) -> bool:
        return self in {self.SUCCEEDED, self.FAILED, self.CANCELLED}


class PlaybookRun(_Model):
    """A single execution of a playbook."""

    uid: str
    playbook_uid: str
    status: PlaybookRunStatus
    started_time: Timestamp | None = None
    ended_time: Timestamp | None = None
    message: str | None = None
    outputs: dict[str, JsonValue] = Field(default_factory=dict)


class Driver:
    """Base class for SOAR drivers.

    Subclasses set :attr:`name`, override the operations their SOAR supports, and may
    override :meth:`describe` to narrow capabilities at runtime (for example by SOAR version
    or API permissions). Drivers that hold connections should override :meth:`aclose`; a
    driver can be used as an async context manager.
    """

    name: ClassVar[str]

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        if not isinstance(getattr(cls, "name", None), str):
            raise TypeError(f"driver {cls.__qualname__} must define a class attribute 'name'")
        return super().__new__(cls)

    @classmethod
    def implemented_capabilities(cls) -> frozenset[Capability]:
        """Capabilities whose methods this driver class overrides."""
        return frozenset(
            c for c in Capability if getattr(cls, c.value) is not getattr(Driver, c.value)
        )

    async def describe(self) -> DriverInfo:
        """Report the driver and its capabilities. Must not claim unimplemented capabilities."""
        return DriverInfo(name=self.name, capabilities=self.implemented_capabilities())

    def _unsupported(self, capability: Capability) -> CapabilityNotSupportedError:
        return CapabilityNotSupportedError(capability, driver=self.name)

    # -- Alerts ---------------------------------------------------------------------------

    async def list_alerts(self, query: AlertQuery | None = None) -> Page[DetectionFinding]:
        """List alerts, newest first."""
        raise self._unsupported(Capability.LIST_ALERTS)

    async def get_alert(self, alert_uid: str) -> DetectionFinding:
        """Fetch one alert by its ``finding_info.uid``."""
        raise self._unsupported(Capability.GET_ALERT)

    # -- Cases ----------------------------------------------------------------------------

    async def get_case(self, case_uid: str) -> IncidentFinding:
        """Fetch one case by its uid."""
        raise self._unsupported(Capability.GET_CASE)

    async def add_note(self, case_uid: str, note: Note) -> Note:
        """Add a note to a case. Returns the note as stored, including any assigned uid."""
        raise self._unsupported(Capability.ADD_NOTE)

    async def close_case(
        self, case_uid: str, *, verdict_id: VerdictId, comment: str | None = None
    ) -> IncidentFinding:
        """Close a case with a verdict. Returns the updated case."""
        raise self._unsupported(Capability.CLOSE_CASE)

    # -- Indicators -----------------------------------------------------------------------

    async def enrich_indicator(self, indicator: Observable) -> IndicatorEnrichment:
        """Look up reputation and context for an indicator using the SOAR's integrations."""
        raise self._unsupported(Capability.ENRICH_INDICATOR)

    # -- Playbooks ------------------------------------------------------------------------

    async def list_playbooks(self) -> list[Playbook]:
        """List playbooks available to run."""
        raise self._unsupported(Capability.LIST_PLAYBOOKS)

    async def run_playbook(
        self,
        playbook_uid: str,
        *,
        case_uid: str | None = None,
        alert_uid: str | None = None,
        inputs: Mapping[str, JsonValue] | None = None,
    ) -> PlaybookRun:
        """Start a playbook, optionally in the context of a case or alert.

        Returns immediately; poll :meth:`get_playbook_run` until the run is finished.
        """
        raise self._unsupported(Capability.RUN_PLAYBOOK)

    async def get_playbook_run(self, run_uid: str) -> PlaybookRun:
        """Fetch the current state of a playbook run."""
        raise self._unsupported(Capability.GET_PLAYBOOK_RUN)

    # -- Lifecycle ------------------------------------------------------------------------

    async def aclose(self) -> None:
        """Release resources such as HTTP connections. Safe to call more than once."""

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
