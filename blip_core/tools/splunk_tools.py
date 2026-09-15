"""
BLIP-AI Core — Splunk Tools
===========================
Typed tool wrappers around the existing SplunkConnector. This is the
only way the investigation agent can touch Splunk: every call passes
through the read-only and max-range guardrails before a query ever
reaches the REST API, and the connector itself is never exposed
directly to the agent.
"""

from typing import Any, Dict

from splunk_connector import SplunkConnector

from blip_core.tools.base import Tool
from blip_core.tools.guardrails import check_max_range, check_read_only_spl

_connector = None


def _get_connector() -> SplunkConnector:
    global _connector
    if _connector is None:
        _connector = SplunkConnector()
    return _connector


def _splunk_search(spl: str, earliest: str = "-1h", latest: str = "now") -> Dict[str, Any]:
    check_read_only_spl(spl)
    check_max_range(earliest, latest)
    results = _get_connector().run_query(spl, earliest=earliest, latest=latest)
    return {"results": results, "count": len(results)}


def _pivot_on_entity(value: str, type: str) -> Dict[str, Any]:
    """
    Pivot on a known entity (a source IP or a Linux AUID) using the
    existing detection queries as building blocks, scoped to a fixed
    24h window — this tool has no free-text query surface at all.
    """
    connector = _get_connector()

    if type == "src_ip":
        brute = [r for r in connector.check_ssh_brute_force(hours=24) if r.get("src_ip") == value]
        scan = connector.check_port_scan(src_ip=value, hours=24)
        recon = [r for r in connector.check_recon_campaign(hours=24) if r.get("src_ip") == value]
        return {
            "entity": value,
            "type": type,
            "brute_force": brute,
            "port_scan": scan,
            "recon_campaign": recon,
        }

    if type == "auid":
        escalation = [r for r in connector.check_privilege_escalation(hours=24) if r.get("auid") == value]
        persistence = [r for r in connector.check_persistence(hours=24) if r.get("auid") == value]
        return {
            "entity": value,
            "type": type,
            "privilege_escalation": escalation,
            "persistence": persistence,
        }

    raise ValueError(f"Unsupported pivot type '{type}' — expected 'src_ip' or 'auid'")


SPLUNK_SEARCH = Tool(
    name="splunk_search",
    description=(
        "Run a read-only SPL search against Splunk and return matching events. "
        "Rejected if the query contains a write/side-effect command or requests "
        "more than 24 hours of lookback."
    ),
    input_schema={
        "type": "object",
        "required": ["spl"],
        "properties": {
            "spl": {"type": "string"},
            "earliest": {"type": "string"},
            "latest": {"type": "string"},
        },
    },
    output_schema={
        "type": "object",
        "required": ["results", "count"],
        "properties": {
            "results": {"type": "array"},
            "count": {"type": "integer"},
        },
    },
    risk_level="read_only",
    handler=_splunk_search,
)

PIVOT_ON_ENTITY = Tool(
    name="pivot_on_entity",
    description=(
        "Look up everything BLIP-AI's existing detections know about a given "
        "entity (a source IP or a Linux AUID) within the last 24 hours."
    ),
    input_schema={
        "type": "object",
        "required": ["value", "type"],
        "properties": {
            "value": {"type": "string"},
            "type": {"type": "string", "enum": ["src_ip", "auid"]},
        },
    },
    output_schema={
        "type": "object",
        "required": ["entity", "type"],
        "properties": {
            "entity": {"type": "string"},
            "type": {"type": "string"},
        },
    },
    risk_level="read_only",
    handler=_pivot_on_entity,
)
