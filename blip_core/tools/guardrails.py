"""
BLIP-AI Core — Query Guardrails
================================
Pure functions enforcing the non-negotiable safety limits on any
Splunk query the investigation agent can issue: read-only SPL only,
and a maximum lookback window. These run before any query reaches
SplunkConnector, and a violation raises rather than silently
truncating, so the agent's transcript always shows the true reason
a tool call failed.
"""

import re

from blip_core.config import MAX_QUERY_HOURS


class GuardrailViolation(Exception):
    """Raised when a tool call would violate a non-negotiable safety limit."""


# Splunk commands that write, export, or trigger side effects. Matched
# against `| <command>` so they're only caught as pipeline stages, not
# as incidental substrings of field names or search terms.
_DISALLOWED_SPL_PATTERNS = [
    r"\|\s*delete\b",
    r"\|\s*outputlookup\b",
    r"\|\s*outputcsv\b",
    r"\|\s*collect\b",
    r"\|\s*sendemail\b",
    r"\|\s*script\b",
    r"\|\s*run\b",
    r"\|\s*map\b",       # can invoke arbitrary sub-searches with side effects
    r"\|\s*savedsearch\b",  # could indirectly trigger a saved search with actions
]

_RELATIVE_TIME_RE = re.compile(r"^-(?P<amount>\d+)(?P<unit>s|m|h|d|w|mon|q|y)$")

_UNIT_TO_HOURS = {
    "s": 1 / 3600,
    "m": 1 / 60,
    "h": 1,
    "d": 24,
    "w": 24 * 7,
    "mon": 24 * 30,
    "q": 24 * 91,
    "y": 24 * 365,
}


def check_read_only_spl(spl: str) -> None:
    """Raise GuardrailViolation if the SPL contains a disallowed write/side-effect command."""
    lowered = spl.lower()
    for pattern in _DISALLOWED_SPL_PATTERNS:
        if re.search(pattern, lowered):
            raise GuardrailViolation(
                f"SPL query contains disallowed command matching '{pattern}': {spl.strip()}"
            )


def check_max_range(earliest: str, latest: str = "now", max_hours: int = MAX_QUERY_HOURS) -> None:
    """
    Raise GuardrailViolation if the requested time range exceeds max_hours.

    Only relative time strings (e.g. '-4h', '-24h') are accepted for
    `earliest`, and `latest` must be 'now' — absolute or open-ended ranges
    are rejected outright since their true span can't be verified without
    a live Splunk round-trip.
    """
    if latest != "now":
        raise GuardrailViolation(
            f"Only latest='now' is permitted for agent-issued queries, got '{latest}'"
        )

    match = _RELATIVE_TIME_RE.match(earliest.strip())
    if not match:
        raise GuardrailViolation(
            f"earliest time '{earliest}' must be a relative time string like '-4h' or '-24h'"
        )

    amount = int(match.group("amount"))
    unit = match.group("unit")
    hours = amount * _UNIT_TO_HOURS[unit]

    if hours > max_hours:
        raise GuardrailViolation(
            f"Requested range of {hours:g}h exceeds the {max_hours}h maximum "
            f"(earliest='{earliest}')"
        )
