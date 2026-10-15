"""Refresh the trimmed OCSF schema snapshot used by the model fidelity tests.

The snapshot records, for each OCSF class and object that anysoar models, the required
attributes and the enum values of every enum attribute. Tests compare anysoar's models
against it, so a schema bump is a reviewable diff rather than silent drift.

Usage:
    uv run python scripts/update_ocsf_snapshot.py [--version 1.9.0]

Profiles are disabled when fetching classes and objects, so only base definitions are captured;
the profiles anysoar uses are captured separately.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_VERSION = "1.9.0"
CLASSES = ["detection_finding", "incident_finding"]
PROFILES = ["incident"]
OBJECTS = [
    "enrichment",
    "finding_info",
    "group",
    "metadata",
    "note",
    "observable",
    "product",
    "reputation",
    "user",
]
OUT = Path(__file__).parents[1] / "packages/anysoar/tests/fixtures/ocsf/schema_snapshot.json"


def fetch(version: str, kind: str, name: str) -> dict[str, Any]:
    url = f"https://schema.ocsf.io/api/{version}/{kind}/{name}?profiles="
    with urllib.request.urlopen(url, timeout=30) as resp:
        data: dict[str, Any] = json.load(resp)
    return data


def trim(definition: dict[str, Any]) -> dict[str, Any]:
    attributes: dict[str, Any] = definition["attributes"]
    enums = {
        attr: {value: spec["caption"] for value, spec in sorted(meta["enum"].items(), key=_num)}
        for attr, meta in sorted(attributes.items())
        if "enum" in meta
    }
    return {
        "uid": definition.get("uid"),
        "attributes": sorted(attributes),
        "required": sorted(a for a, m in attributes.items() if m.get("requirement") == "required"),
        "constraints": definition.get("constraints") or {},
        "enums": enums,
    }


def _num(item: tuple[str, Any]) -> int:
    return int(item[0])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default=DEFAULT_VERSION)
    args = parser.parse_args()

    snapshot = {
        "version": args.version,
        "source": "https://schema.ocsf.io (base definitions; profiles listed separately)",
        "classes": {name: trim(fetch(args.version, "classes", name)) for name in CLASSES},
        "objects": {name: trim(fetch(args.version, "objects", name)) for name in OBJECTS},
        "profiles": {name: trim(fetch(args.version, "profiles", name)) for name in PROFILES},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snapshot, indent=2) + "\n")
    print(f"Wrote {OUT.relative_to(Path.cwd())} (OCSF {args.version})")


if __name__ == "__main__":
    main()
