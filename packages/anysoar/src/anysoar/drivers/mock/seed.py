"""Synthetic seed data for the mock driver: a morning of user-reported phishing.

Everything here is invented. The organisation under attack is ``example.com``; attacker
infrastructure uses the other reserved domains (``example.net``, ``example.org``, RFC 2606) and
the documentation IP ranges (``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``,
RFC 5737). File hashes are SHA-256 digests of made-up labels, not of real files.

Each builder returns fresh model instances, so every :class:`~anysoar.drivers.mock.MockDriver`
starts from the same state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import JsonValue

from anysoar.interface import ActionTier, Playbook
from anysoar.models import (
    ActivityId,
    ConfidenceId,
    DetectionFinding,
    DetectionFindingStatusId,
    FindingInfo,
    Group,
    IncidentFinding,
    IncidentFindingStatusId,
    Metadata,
    Note,
    Observable,
    ObservableTypeId,
    PriorityId,
    Product,
    ReputationScoreId,
    SeverityId,
    User,
    VerdictId,
    to_timestamp,
)

__all__ = [
    "BASE_TIME",
    "PRODUCT",
    "KnownIndicator",
    "build_alerts",
    "build_cases",
    "build_playbooks",
    "known_indicators",
    "synthetic_hash",
]

BASE_TIME = to_timestamp(datetime(2026, 10, 15, 8, 0, tzinfo=UTC))
"""When the seeded scenario starts: 2026-10-15 08:00 UTC."""

PRODUCT = Product(name="Mock SOAR", vendor_name="anysoar")

_MINUTE = int(timedelta(minutes=1).total_seconds() * 1000)

TIER1 = Group(uid="grp-soc-t1", name="SOC Tier 1")
ANALYST = User(
    uid="usr-analyst-1",
    name="analyst1",
    display_name="Analyst One",
    email_addr="analyst1@example.com",
)
REPORTER_BOT = User(uid="usr-phish-button", name="phish-button")


def synthetic_hash(label: str) -> str:
    """A SHA-256-shaped value derived from a label; stands in for a file hash."""
    return hashlib.sha256(f"anysoar-mock:{label}".encode()).hexdigest()


def _at(minutes: int) -> int:
    return BASE_TIME + minutes * _MINUTE


def _metadata(uid: str) -> Metadata:
    return Metadata(product=PRODUCT.model_copy(), uid=uid, log_name="user-reported-phishing")


def _sender(value: str) -> Observable:
    return Observable(name="email.from", type_id=ObservableTypeId.EMAIL_ADDRESS, value=value)


def _recipient(value: str) -> Observable:
    return Observable(name="email.to", type_id=ObservableTypeId.EMAIL_ADDRESS, value=value)


def _url(value: str) -> Observable:
    return Observable(name="email.urls", type_id=ObservableTypeId.URL_STRING, value=value)


def _ip(value: str) -> Observable:
    return Observable(name="src_endpoint.ip", type_id=ObservableTypeId.IP_ADDRESS, value=value)


def _hash(label: str) -> Observable:
    return Observable(
        name="file.hashes", type_id=ObservableTypeId.HASH, value=synthetic_hash(label)
    )


@dataclass(frozen=True)
class _AlertSeed:
    uid: str
    minutes: int
    title: str
    desc: str
    severity_id: SeverityId
    status_id: DetectionFindingStatusId
    observables: tuple[Observable, ...]
    types: tuple[str, ...] = ("Phishing",)
    confidence_id: ConfidenceId = ConfidenceId.MEDIUM


_ALERTS = (
    _AlertSeed(
        uid="alert-0001",
        minutes=0,
        title='Reported phishing: "Your mailbox is almost full"',
        desc="Credential-harvesting link sent to alice@example.com, posing as IT support.",
        severity_id=SeverityId.HIGH,
        status_id=DetectionFindingStatusId.IN_PROGRESS,
        confidence_id=ConfidenceId.HIGH,
        observables=(
            _sender("it-support@example.net"),
            _recipient("alice@example.com"),
            _url("https://login.example.net/owa/verify"),
            _ip("203.0.113.25"),
        ),
    ),
    _AlertSeed(
        uid="alert-0002",
        minutes=7,
        title='Reported phishing: "Your mailbox is almost full"',
        desc="Same lure as alert-0001, reported by bob@example.com.",
        severity_id=SeverityId.HIGH,
        status_id=DetectionFindingStatusId.IN_PROGRESS,
        confidence_id=ConfidenceId.HIGH,
        observables=(
            _sender("it-support@example.net"),
            _recipient("bob@example.com"),
            _url("https://login.example.net/owa/verify"),
            _ip("203.0.113.25"),
        ),
    ),
    _AlertSeed(
        uid="alert-0003",
        minutes=24,
        title='Reported phishing: "Invoice INV-20431 overdue"',
        desc="HTML attachment from an unknown supplier sent to accounts@example.com.",
        severity_id=SeverityId.MEDIUM,
        status_id=DetectionFindingStatusId.NEW,
        observables=(
            _sender("billing@example.org"),
            _recipient("accounts@example.com"),
            _hash("invoice-INV-20431.html"),
            _ip("198.51.100.7"),
        ),
    ),
    _AlertSeed(
        uid="alert-0004",
        minutes=41,
        title='Reported phishing: "Example Weekly newsletter"',
        desc="Newsletter from the company's own marketing domain, reported by carol@example.com.",
        severity_id=SeverityId.LOW,
        status_id=DetectionFindingStatusId.NEW,
        confidence_id=ConfidenceId.LOW,
        observables=(
            _sender("news@example.com"),
            _recipient("carol@example.com"),
            _url("https://www.example.com/newsletter/2026-10"),
            _ip("192.0.2.10"),
        ),
    ),
    _AlertSeed(
        uid="alert-0005",
        minutes=58,
        title='Reported phishing: "Dave shared a document with you"',
        desc="File-share lure linking to a look-alike sign-in page, sent to dave@example.com.",
        severity_id=SeverityId.MEDIUM,
        status_id=DetectionFindingStatusId.NEW,
        observables=(
            _sender("no-reply@share.example.net"),
            _recipient("dave@example.com"),
            _url("https://share.example.net/d/7f3a9c"),
            _ip("203.0.113.80"),
        ),
    ),
    _AlertSeed(
        uid="alert-0006",
        minutes=73,
        title='Reported phishing: "Update to payroll bank details"',
        desc="Request to change payroll bank details from a look-alike HR address. No links.",
        severity_id=SeverityId.MEDIUM,
        status_id=DetectionFindingStatusId.RESOLVED,
        types=("Phishing", "Business Email Compromise"),
        observables=(
            _sender("hr-payroll@example.org"),
            _recipient("erin@example.com"),
            _ip("198.51.100.44"),
        ),
    ),
    _AlertSeed(
        uid="alert-0007",
        minutes=95,
        title='Reported phishing: "Annual security awareness check"',
        desc="Internal phishing simulation email reported by frank@example.com.",
        severity_id=SeverityId.INFORMATIONAL,
        status_id=DetectionFindingStatusId.SUPPRESSED,
        confidence_id=ConfidenceId.HIGH,
        types=("Phishing", "Simulation"),
        observables=(
            _sender("training@example.com"),
            _recipient("frank@example.com"),
            _url("https://training.example.com/landing/q4"),
        ),
    ),
    _AlertSeed(
        uid="alert-0008",
        minutes=112,
        title='Reported phishing: "Your password expires today"',
        desc="Password-reset lure linking to a bare IP address, sent to grace@example.com.",
        severity_id=SeverityId.HIGH,
        status_id=DetectionFindingStatusId.NEW,
        observables=(
            _sender("noreply@example.net"),
            _recipient("grace@example.com"),
            _url("http://198.51.100.23/reset"),
            _ip("198.51.100.23"),
        ),
    ),
)


def build_alerts() -> list[DetectionFinding]:
    """The seeded alerts, newest first."""
    alerts = []
    for seed in _ALERTS:
        time = _at(seed.minutes)
        alerts.append(
            DetectionFinding(
                activity_id=ActivityId.CREATE,
                severity_id=seed.severity_id,
                status_id=seed.status_id,
                confidence_id=seed.confidence_id,
                is_alert=True,
                time=time,
                message=seed.title,
                metadata=_metadata(f"evt-{seed.uid}"),
                finding_info=FindingInfo(
                    uid=seed.uid,
                    title=seed.title,
                    desc=seed.desc,
                    types=list(seed.types),
                    created_time=time,
                ),
                observables=[o.model_copy() for o in seed.observables],
                notes=[
                    Note(
                        comment="Reported via the phishing button.",
                        owner=REPORTER_BOT.model_copy(),
                        created_time=time,
                    )
                ],
            )
        )
    return sorted(alerts, key=lambda a: a.time, reverse=True)


def build_cases(alerts: list[DetectionFinding]) -> list[IncidentFinding]:
    """The seeded cases, grouping some of ``alerts``."""
    by_uid = {a.finding_info.uid: a for a in alerts}

    def infos(*uids: str) -> list[FindingInfo]:
        return [by_uid[u].finding_info.model_copy() for u in uids]

    def observables(*uids: str) -> list[Observable]:
        unique: dict[tuple[int, str | None], Observable] = {}
        for uid in uids:
            for o in by_uid[uid].observables:
                unique.setdefault((o.type_id, o.value), o.model_copy())
        return list(unique.values())

    return [
        IncidentFinding(
            activity_id=ActivityId.UPDATE,
            severity_id=SeverityId.HIGH,
            status_id=IncidentFindingStatusId.IN_PROGRESS,
            priority_id=PriorityId.HIGH,
            time=_at(15),
            start_time=_at(0),
            message="Credential phishing campaign: mailbox quota lure",
            desc="Two users reported the same credential-harvesting email from example.net.",
            metadata=_metadata("case-0001"),
            assignee=ANALYST.model_copy(),
            assignee_group=TIER1.model_copy(),
            notes=[
                Note(
                    uid="note-seed-0001",
                    comment="Grouped alert-0001 and alert-0002: same sender, URL and source IP.",
                    owner=ANALYST.model_copy(),
                    created_time=_at(15),
                )
            ],
            finding_info_list=infos("alert-0001", "alert-0002"),
            observables=observables("alert-0001", "alert-0002"),
        ),
        IncidentFinding(
            activity_id=ActivityId.CREATE,
            severity_id=SeverityId.MEDIUM,
            status_id=IncidentFindingStatusId.NEW,
            priority_id=PriorityId.MEDIUM,
            time=_at(25),
            start_time=_at(24),
            message="Suspicious invoice attachment",
            desc="HTML invoice attachment from an unknown supplier domain.",
            metadata=_metadata("case-0002"),
            finding_info_list=infos("alert-0003"),
            observables=observables("alert-0003"),
        ),
        IncidentFinding(
            activity_id=ActivityId.CLOSE,
            severity_id=SeverityId.MEDIUM,
            status_id=IncidentFindingStatusId.CLOSED,
            priority_id=PriorityId.MEDIUM,
            verdict_id=VerdictId.TRUE_POSITIVE,
            time=_at(90),
            start_time=_at(73),
            end_time=_at(90),
            message="Payroll diversion attempt",
            desc="Look-alike HR address asked to change payroll bank details.",
            comment="Sender blocked; employee confirmed no details were changed.",
            metadata=_metadata("case-0003"),
            assignee=ANALYST.model_copy(),
            assignee_group=TIER1.model_copy(),
            finding_info_list=infos("alert-0006"),
            observables=observables("alert-0006"),
        ),
    ]


def build_playbooks() -> list[Playbook]:
    """The playbooks the mock SOAR can run."""

    def schema(**properties: str) -> dict[str, JsonValue]:
        return {
            "type": "object",
            "properties": {
                name: {"type": "string", "description": d} for name, d in properties.items()
            },
            "required": list(properties),
        }

    return [
        Playbook(
            uid="pb-block-sender",
            name="Block sender",
            description="Add a sender address to the mail gateway block list.",
            input_schema=schema(sender="Email address to block."),
        ),
        Playbook(
            uid="pb-block-url",
            name="Block URL",
            description="Add a URL to the web proxy block list.",
            input_schema=schema(url="URL to block."),
        ),
        Playbook(
            uid="pb-quarantine-email",
            name="Quarantine reported email",
            description="Move every copy of the reported email to quarantine. Reversible.",
            input_schema=schema(sender="Sender of the email.", subject="Subject of the email."),
        ),
        Playbook(
            uid="pb-notify-reporter",
            name="Notify reporter",
            description="Thank the user who reported the email and tell them the outcome.",
        ),
        Playbook(
            uid="pb-disable-account",
            name="Disable user account",
            description="Disable a user's directory account and revoke their sessions.",
            tier=ActionTier.DESTRUCTIVE,
            input_schema=schema(user="Email address of the account to disable."),
        ),
    ]


@dataclass(frozen=True)
class KnownIndicator:
    """A curated reputation for an indicator in the seeded scenario."""

    score_id: ReputationScoreId
    tags: tuple[str, ...] = ()


def known_indicators() -> dict[tuple[ObservableTypeId, str], KnownIndicator]:
    """Curated reputations for indicators in the scenario, keyed by ``(type_id, value)``."""
    malicious = ReputationScoreId.MALICIOUS
    likely = ReputationScoreId.PROBABLY_MALICIOUS
    suspicious = ReputationScoreId.SUSPICIOUS_RISKY
    safe = ReputationScoreId.SAFE
    email, url = ObservableTypeId.EMAIL_ADDRESS, ObservableTypeId.URL_STRING
    ip, file_hash = ObservableTypeId.IP_ADDRESS, ObservableTypeId.HASH
    return {
        (email, "it-support@example.net"): KnownIndicator(malicious, ("credential-phishing",)),
        (url, "https://login.example.net/owa/verify"): KnownIndicator(
            malicious, ("credential-phishing",)
        ),
        (ip, "203.0.113.25"): KnownIndicator(likely, ("phishing-infrastructure",)),
        (email, "billing@example.org"): KnownIndicator(suspicious, ("newly-registered-domain",)),
        (file_hash, synthetic_hash("invoice-INV-20431.html")): KnownIndicator(
            likely, ("html-smuggling",)
        ),
        (ip, "198.51.100.7"): KnownIndicator(suspicious),
        (email, "news@example.com"): KnownIndicator(safe, ("internal",)),
        (url, "https://www.example.com/newsletter/2026-10"): KnownIndicator(safe, ("internal",)),
        (ip, "192.0.2.10"): KnownIndicator(safe, ("internal",)),
        (email, "no-reply@share.example.net"): KnownIndicator(likely, ("credential-phishing",)),
        (url, "https://share.example.net/d/7f3a9c"): KnownIndicator(
            likely, ("credential-phishing",)
        ),
        (ip, "203.0.113.80"): KnownIndicator(suspicious),
        (email, "hr-payroll@example.org"): KnownIndicator(malicious, ("bec", "look-alike")),
        (ip, "198.51.100.44"): KnownIndicator(suspicious),
        (email, "training@example.com"): KnownIndicator(safe, ("phishing-simulation",)),
        (url, "https://training.example.com/landing/q4"): KnownIndicator(
            safe, ("phishing-simulation",)
        ),
        (email, "noreply@example.net"): KnownIndicator(likely, ("credential-phishing",)),
        (url, "http://198.51.100.23/reset"): KnownIndicator(malicious, ("credential-phishing",)),
        (ip, "198.51.100.23"): KnownIndicator(malicious, ("phishing-infrastructure",)),
    }
