"""Datetime helpers shared by the orphan collectors.

The collectors deal with timestamps from three different shapes:
* boto3 ``datetime`` objects (IAM ``CreateDate``, ``RoleLastUsed.LastUsedDate``)
* ISO strings with ``Z`` or ``+0000`` offsets (Lambda ``LastModified``)
* ``None`` when the field is missing

These helpers normalize all three so the per-service collectors can stay
focused on their domain logic instead of reimplementing the same parsing.
"""

import logging
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


def format_datetime(value: datetime | str | None) -> str | None:
    """Normalize a datetime (or already-ISO string) to an ISO 8601 string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def parse_iso_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp into a timezone-aware datetime.

    Accepts the variants AWS APIs actually emit, including a trailing ``Z``
    (which ``datetime.fromisoformat`` rejects on Python < 3.11 and is still
    fragile to read directly). Returns None on missing/unparseable input.
    """
    if not value:
        return None

    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        logger.debug("Could not parse timestamp value: %s", value)
        return None


def days_since(value: datetime | str | None) -> int | None:
    """Whole days between ``value`` (UTC if naive) and now. None if unparsable."""
    if value is None:
        return None
    if isinstance(value, str):
        parsed = parse_iso_timestamp(value)
        if parsed is None:
            return None
        value = parsed
    if not isinstance(value, datetime):
        return None

    now = datetime.now(UTC)
    reference = value if value.tzinfo else value.replace(tzinfo=UTC)
    delta = now - reference
    return max(delta.days, 0)
