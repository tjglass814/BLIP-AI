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


# Known-safe, read-only SPL commands. Every pipeline stage in an
# agent-issued query must start with one of these. This is an allowlist,
# not a denylist: an unrecognized command fails closed (rejected) rather
# than silently passing through, so a new or overlooked write/side-effect
# command (e.g. a future Splunk release adding one) can never slip past
# this guardrail the way it could with a denylist of known-bad commands.
_ALLOWED_SPL_COMMANDS = frozenset(
    {
        "search",
        "stats",
        "eval",
        "where",
        "table",
        "fields",
        "sort",
        "dedup",
        "head",
        "tail",
        "top",
        "rare",
        "timechart",
        "chart",
        "bin",
        "bucket",
        "rename",
        "regex",
        "rex",
        "convert",
        "fillnull",
        "filldown",
        "format",
        "mvexpand",
        "spath",
        "streamstats",
        "eventstats",
        "transaction",
        "addinfo",
        "makemv",
        "nomv",
        "strcat",
        "iplocation",
    }
)

_COMMAND_TOKEN_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)")

# An SPL query can embed its own earliest=/latest= time modifiers inline
# (e.g. "search index=main earliest=-90d"), which Splunk honors in
# addition to — and independent of — the earliest/latest tool
# parameters. Allowing these would let check_max_range's 24h cap be
# bypassed entirely by an agent that simply writes the wider range into
# the query text instead of the earliest/latest arguments.
_EMBEDDED_TIME_MODIFIER_RE = re.compile(r"\b(earliest|latest)\s*=")

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
    """
    Raise GuardrailViolation unless every pipeline stage in the SPL is a
    known-safe, read-only command.

    The first stage is treated specially: it may be an explicit `search`
    command, or an implicit search with no leading command keyword at
    all (e.g. `index=main sourcetype=...`), which is how most SPL
    queries are written and is inherently read-only. Every stage after a
    `|` must start with a command from the allowlist.
    """
    stages = spl.split("|")

    first = stages[0].strip()
    if first:
        match = _COMMAND_TOKEN_RE.match(first)
        if match:
            token = match.group(1).lower()
            rest = first[match.end():].lstrip()
            is_field_value_pair = rest.startswith("=")
            if token != "search" and not is_field_value_pair and token not in _ALLOWED_SPL_COMMANDS:
                raise GuardrailViolation(
                    f"SPL command '{token}' is not on the allowed read-only command list: {spl.strip()}"
                )

    for stage in stages[1:]:
        stripped = stage.strip()
        if not stripped:
            continue
        match = _COMMAND_TOKEN_RE.match(stripped)
        token = match.group(1).lower() if match else ""
        if token not in _ALLOWED_SPL_COMMANDS:
            raise GuardrailViolation(
                f"SPL command '{token or stripped}' is not on the allowed read-only command list: {spl.strip()}"
            )


def check_no_embedded_time_modifiers(spl: str) -> None:
    """
    Raise GuardrailViolation if the SPL text itself sets an earliest= or
    latest= modifier, rather than relying solely on the earliest/latest
    tool parameters that check_max_range enforces.
    """
    match = _EMBEDDED_TIME_MODIFIER_RE.search(spl.lower())
    if match:
        raise GuardrailViolation(
            f"SPL query must not embed its own '{match.group(1)}=' time modifier — "
            f"use the earliest/latest tool parameters instead, which are capped: {spl.strip()}"
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
