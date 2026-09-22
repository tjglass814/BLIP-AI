"""
BLIP-AI Core — Investigation Loop
==================================
Top-level orchestrator: receive alert -> run the governed agent
(llm/agent.py) against the typed tool layer (tools/) -> compute
confidence and MITRE mapping deterministically
(deterministic/confidence.py, deterministic/mitre.py) -> run the
policy seam (deterministic/policy.py) -> return the Verdict.

registry, llm_client, and max_iterations are all injectable so tests
never need a live Splunk connection or a live Claude API key — only
investigate()'s defaults touch either.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from blip_core.audit.log import AuditLog
from blip_core.config import MAX_ITERATIONS
from blip_core.deterministic.confidence import compute_confidence
from blip_core.deterministic.evidence_tags import confidence_weight_for
from blip_core.deterministic.mitre import map_evidence_to_techniques
from blip_core.deterministic.policy import decide
from blip_core.llm.agent import CONCLUDE_TOOL, AnthropicLLMClient, InvestigationAgent, LLMClient
from blip_core.tools.registry import ToolRegistry
from blip_core.tools.splunk_tools import PIVOT_ON_ENTITY, SPLUNK_SEARCH
from blip_core.verdict.schema import EvidenceItem, Verdict


def default_tool_registry(audit_log: Optional[AuditLog] = None) -> ToolRegistry:
    """The standard tool set: the Splunk tools plus conclude_investigation."""
    registry = ToolRegistry(audit_log=audit_log)
    for tool in (SPLUNK_SEARCH, PIVOT_ON_ENTITY, CONCLUDE_TOOL):
        registry.register(tool)
    return registry


def _build_evidence_items(raw_evidence: List[Dict[str, Any]]) -> List[EvidenceItem]:
    """
    Turn the LLM's tagged findings into EvidenceItems, assigning each
    one's confidence_contribution from the deterministic weight table —
    never from anything the LLM supplied.
    """
    return [
        EvidenceItem(
            source=item["source"],
            tag=item["tag"],
            detail=item.get("detail", {}),
            confidence_contribution=confidence_weight_for(item["tag"]),
        )
        for item in raw_evidence
    ]


def investigate(
    alert_name: str,
    registry: Optional[ToolRegistry] = None,
    llm_client: Optional[LLMClient] = None,
    max_iterations: int = MAX_ITERATIONS,
) -> Verdict:
    """
    Run one governed investigation end to end and return its Verdict.

    Defaults to the real Splunk-backed registry and a real Claude
    tool-use client — pass fakes in tests to avoid touching either
    live system.
    """
    registry = registry or default_tool_registry()
    llm_client = llm_client or AnthropicLLMClient(tools=registry.list_tools())

    agent = InvestigationAgent(registry=registry, llm_client=llm_client, max_iterations=max_iterations)
    result = agent.run(alert_name)

    # KNOWN ISSUE (see blip_core/KNOWN_ISSUES.md): on MAX_ITERATIONS_REACHED,
    # result.raw_evidence is always [] regardless of what earlier tool calls
    # found, so this verdict scores 0.0 / INFORMATIONAL — indistinguishable
    # from a clean alert. Not fixed here.
    evidence_items = _build_evidence_items(result.raw_evidence)
    confidence_score, confidence_breakdown = compute_confidence(evidence_items)
    mitre_techniques = map_evidence_to_techniques(evidence_items)

    now = datetime.now(timezone.utc)
    verdict_id = f"{alert_name.replace(' ', '_').replace('/', '_')[:50]}_{now.strftime('%Y%m%d_%H%M%S')}"

    verdict = Verdict(
        verdict_id=verdict_id,
        alert_name=alert_name,
        created_at=now.isoformat(),
        status=result.status,
        iterations_used=result.iterations_used,
        max_iterations=max_iterations,
        tool_transcript=result.transcript,
        evidence=evidence_items,
        confidence_score=confidence_score,
        confidence_breakdown=confidence_breakdown,
        mitre_techniques=mitre_techniques,
        llm_reasoning_narrative=result.narrative,
        policy_decision=None,
    )
    verdict.policy_decision = decide(verdict)
    return verdict
