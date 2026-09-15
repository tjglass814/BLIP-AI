"""
BLIP-AI Core — Policy Seam
==========================
The only place a verdict is turned into a decision about what happens
next. In v1 this is intentionally trivial — always RECOMMEND, never
auto-execute — but it lives in its own module because the real policy
engine (confidence + evidence quality + reversibility + asset
criticality + blast radius) grows here later without touching the
agent loop or the confidence math.
"""

from datetime import datetime, timezone

from blip_core.verdict.schema import PolicyDecision, Verdict


def decide(verdict: Verdict) -> PolicyDecision:
    """
    Decide what BLIP-AI should do with a completed investigation.

    v1: always RECOMMEND. No confidence threshold, evidence-quality check,
    or reversibility analysis is consulted yet — those are the seams this
    function grows into, not something callers should assume exists.
    """
    return PolicyDecision(
        decision="RECOMMEND",
        rationale=(
            f"BLIP-AI policy v1 does not auto-execute — every investigation "
            f"(confidence={verdict.confidence_score}) is surfaced to an analyst "
            f"for manual action."
        ),
        evaluated_at=datetime.now(timezone.utc).isoformat(),
    )
