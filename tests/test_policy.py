from blip_core.deterministic.policy import decide
from blip_core.verdict.schema import Verdict


def make_verdict(confidence=0.5):
    return Verdict(
        verdict_id="test_1",
        alert_name="Test Alert",
        created_at="2026-09-15T00:00:00Z",
        status="CONCLUDED",
        iterations_used=1,
        max_iterations=5,
        tool_transcript=[],
        evidence=[],
        confidence_score=confidence,
        confidence_breakdown=[],
        mitre_techniques=[],
        llm_reasoning_narrative="test narrative",
        policy_decision=None,  # not yet decided
    )


def test_policy_always_recommends_regardless_of_confidence():
    for confidence in (0.0, 0.5, 0.9, 1.0):
        decision = decide(make_verdict(confidence))
        assert decision.decision == "RECOMMEND"


def test_policy_rationale_mentions_confidence():
    decision = decide(make_verdict(0.95))
    assert "0.95" in decision.rationale


def test_policy_decision_has_a_timestamp():
    decision = decide(make_verdict())
    assert decision.evaluated_at  # non-empty ISO timestamp
