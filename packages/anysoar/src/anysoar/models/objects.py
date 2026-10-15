"""OCSF objects used by anysoar's findings: metadata, finding info, observables and more."""

from __future__ import annotations

from typing import Self

from pydantic import Field, JsonValue, model_validator

from anysoar.models._base import OCSF_VERSION, OcsfModel, Timestamp
from anysoar.models.enums import ObservableTypeId, ReputationScoreId, UserTypeId

__all__ = [
    "Enrichment",
    "FindingInfo",
    "Group",
    "Metadata",
    "Note",
    "Observable",
    "Product",
    "Reputation",
    "User",
]


def _require_one_of(model: OcsfModel, *names: str) -> None:
    extra = model.model_extra or {}
    if all(getattr(model, n, None) is None and extra.get(n) is None for n in names):
        raise ValueError(f"{type(model).__name__} requires at least one of: {', '.join(names)}")


class Product(OcsfModel):
    """OCSF ``product``: the product that reported the event, e.g. the SOAR platform."""

    name: str | None = None
    uid: str | None = None
    vendor_name: str | None = None
    version: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> Self:
        _require_one_of(self, "name", "uid")
        return self


class Metadata(OcsfModel):
    """OCSF ``metadata``: schema version, reporting product and event identity."""

    version: str = OCSF_VERSION
    product: Product
    profiles: list[str] = Field(default_factory=list)
    uid: str | None = None
    tenant_uid: str | None = None


class FindingInfo(OcsfModel):
    """OCSF ``finding_info``: identity and description of a finding."""

    uid: str
    title: str | None = None
    desc: str | None = None
    types: list[str] = Field(default_factory=list)
    created_time: Timestamp | None = None
    modified_time: Timestamp | None = None
    first_seen_time: Timestamp | None = None
    last_seen_time: Timestamp | None = None
    src_url: str | None = None


class Reputation(OcsfModel):
    """OCSF ``reputation``: a normalized reputation verdict from a provider."""

    base_score: float
    score_id: ReputationScoreId
    provider: str | None = None


class Observable(OcsfModel):
    """OCSF ``observable``: an indicator such as an IP address, domain, URL or file hash."""

    type_id: ObservableTypeId
    value: str | None = None
    name: str | None = None
    """Path of the field the value was observed in, e.g. ``email.from``."""
    type: str | None = None
    reputation: Reputation | None = None


class Enrichment(OcsfModel):
    """OCSF ``enrichment``: additional context about an observed value."""

    name: str
    """Path of the enriched attribute, e.g. ``url.domain``."""
    value: str
    data: JsonValue
    provider: str | None = None
    type: str | None = None
    short_desc: str | None = None
    src_url: str | None = None
    created_time: Timestamp | None = None


class User(OcsfModel):
    """OCSF ``user``: an analyst, assignee or other account."""

    uid: str | None = None
    name: str | None = None
    display_name: str | None = None
    email_addr: str | None = None
    type_id: UserTypeId | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> Self:
        _require_one_of(self, "account", "name", "uid")
        return self


class Group(OcsfModel):
    """OCSF ``group``: e.g. the team a case is assigned to."""

    uid: str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> Self:
        _require_one_of(self, "name", "uid")
        return self


class Note(OcsfModel):
    """OCSF ``note``: a comment attached to a finding, e.g. an analyst's triage note."""

    comment: str
    uid: str | None = None
    title: str | None = None
    owner: User | None = None
    created_time: Timestamp | None = None
    modified_time: Timestamp | None = None
