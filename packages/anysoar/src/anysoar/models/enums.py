"""OCSF enumerations used by anysoar models.

Values and member names match OCSF 1.9.0 exactly; ``tests/test_ocsf_fidelity.py`` checks this
against the schema snapshot. Member names are the OCSF captions in UPPER_SNAKE_CASE.
"""

from enum import IntEnum

__all__ = [
    "ActivityId",
    "ConfidenceId",
    "DetectionFindingStatusId",
    "ImpactId",
    "IncidentFindingStatusId",
    "ObservableTypeId",
    "PriorityId",
    "ReputationScoreId",
    "SeverityId",
    "UserTypeId",
    "VerdictId",
]


class ActivityId(IntEnum):
    """Finding activity (`activity_id`); identical for Detection and Incident Findings."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class SeverityId(IntEnum):
    """Normalized severity (`severity_id`)."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class ConfidenceId(IntEnum):
    """Confidence in the finding (`confidence_id`)."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    OTHER = 99


class ImpactId(IntEnum):
    """Normalized impact (`impact_id`)."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    OTHER = 99


class PriorityId(IntEnum):
    """Normalized priority (`priority_id`)."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    OTHER = 99


class VerdictId(IntEnum):
    """Analyst or system verdict (`verdict_id`)."""

    UNKNOWN = 0
    FALSE_POSITIVE = 1
    TRUE_POSITIVE = 2
    DISREGARD = 3
    SUSPICIOUS = 4
    BENIGN = 5
    TEST = 6
    INSUFFICIENT_DATA = 7
    SECURITY_RISK = 8
    MANAGED_EXTERNALLY = 9
    DUPLICATE = 10
    OTHER = 99


class DetectionFindingStatusId(IntEnum):
    """Status of a Detection Finding, i.e. an alert (`status_id`).

    Differs from :class:`IncidentFindingStatusId`: 3 is Suppressed here but On Hold there."""

    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    SUPPRESSED = 3
    RESOLVED = 4
    ARCHIVED = 5
    DELETED = 6
    OTHER = 99


class IncidentFindingStatusId(IntEnum):
    """Status of an Incident Finding, i.e. a case (`status_id`)."""

    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    ON_HOLD = 3
    RESOLVED = 4
    CLOSED = 5
    OTHER = 99


class ObservableTypeId(IntEnum):
    """Type of an observable, i.e. an indicator (`observable.type_id`)."""

    UNKNOWN = 0
    HOSTNAME = 1
    IP_ADDRESS = 2
    MAC_ADDRESS = 3
    USER_NAME = 4
    EMAIL_ADDRESS = 5
    URL_STRING = 6
    FILE_NAME = 7
    HASH = 8
    PROCESS_NAME = 9
    RESOURCE_UID = 10
    PORT = 11
    SUBNET = 12
    COMMAND_LINE = 13
    COUNTRY = 14
    PROCESS_ID = 15
    HTTP_USER_AGENT = 16
    CWE_OBJECT_UID = 17
    CVE_OBJECT_UID = 18
    USER_CREDENTIAL_ID = 19
    ENDPOINT = 20
    USER = 21
    EMAIL = 22
    UNIFORM_RESOURCE_LOCATOR = 23
    FILE = 24
    PROCESS = 25
    GEO_LOCATION = 26
    CONTAINER = 27
    REGISTRY_KEY = 28
    REGISTRY_VALUE = 29
    FINGERPRINT = 30
    USER_OBJECT_UID = 31
    GROUP_OBJECT_NAME = 32
    GROUP_OBJECT_UID = 33
    ACCOUNT_OBJECT_NAME = 34
    ACCOUNT_OBJECT_UID = 35
    SCRIPT_CONTENT = 36
    SERIAL_NUMBER = 37
    RESOURCE_DETAILS_OBJECT_NAME = 38
    PROCESS_ENTITY_OBJECT_UID = 39
    EMAIL_OBJECT_SUBJECT = 40
    EMAIL_OBJECT_UID = 41
    MESSAGE_UID = 42
    REGISTRY_VALUE_OBJECT_NAME = 43
    ADVISORY_OBJECT_UID = 44
    FILE_PATH = 45
    REGISTRY_KEY_PATH = 46
    DEVICE_OBJECT_UID = 47
    NETWORK_ENDPOINT_OBJECT_UID = 48
    IAM_ROLE_OBJECT_NAME = 49
    IAM_ROLE_OBJECT_UID = 50
    OTHER = 99


class ReputationScoreId(IntEnum):
    """Normalized reputation score (`reputation.score_id`)."""

    UNKNOWN = 0
    VERY_SAFE = 1
    SAFE = 2
    PROBABLY_SAFE = 3
    LEANS_SAFE = 4
    MAY_NOT_BE_SAFE = 5
    EXERCISE_CAUTION = 6
    SUSPICIOUS_RISKY = 7
    POSSIBLY_MALICIOUS = 8
    PROBABLY_MALICIOUS = 9
    MALICIOUS = 10
    OTHER = 99


class UserTypeId(IntEnum):
    """Type of user account (`user.type_id`)."""

    UNKNOWN = 0
    USER = 1
    ADMIN = 2
    SYSTEM = 3
    SERVICE = 4
    OTHER = 99
