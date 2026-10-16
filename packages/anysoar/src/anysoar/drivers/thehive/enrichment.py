"""Cortex analyzer reports, run through TheHive, as anysoar enrichments.

TheHive runs Cortex analyzers on observables, the indicators on its alerts and cases. A
finished job's report holds the analyzer's full output; the short verdicts, *taxonomies*
such as ``DShield Score = 0 count(s)`` with a level of info, safe, suspicious or malicious,
are kept on the observable under the analyzer's name.
"""

from __future__ import annotations

from typing import Any

from anysoar.drivers.thehive.alerts import OBSERVABLE_TYPES
from anysoar.models import Enrichment, Observable, Reputation, ReputationScoreId

__all__ = ["PROVIDER", "data_types", "reputation", "taxonomies", "to_enrichment"]

PROVIDER = "Cortex"

_LEVELS = {
    "safe": ReputationScoreId.SAFE,
    "suspicious": ReputationScoreId.SUSPICIOUS_RISKY,
    "malicious": ReputationScoreId.MALICIOUS,
}
"""Taxonomy levels that say something about reputation; ``info`` does not."""


def data_types(indicator: Observable) -> list[str]:
    """The TheHive observable types an indicator may be stored as, most likely first."""
    candidates = [t for t, ocsf in OBSERVABLE_TYPES.items() if ocsf == indicator.type_id]
    if indicator.type in candidates:
        candidates.remove(indicator.type)
        candidates.insert(0, indicator.type)
    return candidates


def taxonomies(job: dict[str, Any], reports: dict[str, Any]) -> list[dict[str, Any]]:
    """The taxonomies a finished job left in its observable's ``reports``."""
    if job.get("status") != "Success":
        return []
    found: list[dict[str, Any]] = (reports.get(str(job.get("analyzerName"))) or {}).get(
        "taxonomies"
    ) or []
    return found


def _taxonomy_text(taxonomy: dict[str, Any]) -> str:
    return (
        f"{taxonomy.get('namespace')} {taxonomy.get('predicate')}: {taxonomy.get('value')} "
        f"({taxonomy.get('level')})"
    )


def reputation(taxonomies: list[dict[str, Any]]) -> Reputation | None:
    """The worst reputation the taxonomies give, or None if none of them gives one."""
    scores = [_LEVELS[str(t.get("level"))] for t in taxonomies if t.get("level") in _LEVELS]
    if not scores:
        return None
    worst = max(scores)
    return Reputation(base_score=float(worst * 10), score_id=worst, provider=PROVIDER)


def to_enrichment(
    job: dict[str, Any], taxonomies: list[dict[str, Any]], *, name: str, value: str
) -> Enrichment:
    """An enrichment from a Cortex job TheHive ran, finished or not."""
    analyzer = str(job.get("analyzerName") or job.get("analyzerId"))
    status = job.get("status")
    report = job.get("report") or {}
    data: Any
    if status == "Success":
        data = report.get("full")
        summary = "; ".join(_taxonomy_text(t) for t in taxonomies) or None
    elif status == "Failure":
        error = str(report.get("errorMessage") or "").strip()
        data = {"error": error}
        # Analyzer errors are often Python tracebacks; the last line says what went wrong.
        summary = f"failed: {error.splitlines()[-1] if error else 'no reason given'}"
    else:
        data = {"status": status}
        summary = "did not finish in time"
    return Enrichment(
        name=name,
        value=value,
        data=data,
        provider=analyzer,
        type="cortex-analyzer",
        short_desc=summary,
        created_time=job.get("endDate"),
    )
