"""Shared base model and helpers for OCSF-aligned models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer

OCSF_VERSION = "1.9.0"
"""The OCSF schema version anysoar's models are aligned with."""

Timestamp = Annotated[int, Field(ge=0, description="OCSF timestamp_t: milliseconds since epoch.")]


def to_timestamp(dt: datetime) -> int:
    """Convert an aware datetime to an OCSF timestamp (milliseconds since the epoch)."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return int(dt.timestamp() * 1000)


def from_timestamp(ts: int) -> datetime:
    """Convert an OCSF timestamp (milliseconds since the epoch) to an aware UTC datetime."""
    return datetime.fromtimestamp(ts / 1000, tz=UTC)


def now_timestamp() -> int:
    """The current time as an OCSF timestamp."""
    return to_timestamp(datetime.now(UTC))


class OcsfModel(BaseModel):
    """Base for all OCSF-aligned models.

    Attributes OCSF defines but anysoar does not model are preserved (``extra="allow"``), so
    a full OCSF payload survives a parse/serialize round trip. Serialization follows OCSF
    conventions: unset attributes and empty arrays are omitted, enums are emitted as integers.
    """

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    @classmethod
    def from_ocsf(cls, data: dict[str, Any]) -> Self:
        """Parse an OCSF JSON object."""
        return cls.model_validate(data)

    def to_ocsf(self) -> dict[str, Any]:
        """Serialize to an OCSF JSON object."""
        return self.model_dump(mode="json")

    def ocsf_profiles(self) -> set[str]:
        """OCSF profiles whose attributes are set on this model. Overridden where relevant."""
        return set()

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        fields = type(self).model_fields
        for key in [k for k, v in data.items() if k in fields and (v is None or v == [])]:
            del data[key]
        profiles = self.ocsf_profiles()
        metadata = data.get("metadata")
        if profiles and isinstance(metadata, dict):
            metadata["profiles"] = sorted(set(metadata.get("profiles", [])) | profiles)
        return data
