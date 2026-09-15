import pytest

from blip_core.verdict.schema import EvidenceItem, MitreMapping, PolicyDecision, Verdict


def test_evidence_item_rejects_unknown_source():
    with pytest.raises(ValueError):
        EvidenceItem(source="not_a_real_source", tag="x", detail={}, confidence_contribution=0.1)


def test_evidence_item_accepts_known_source():
    item = EvidenceItem(source="auditd_host", tag="priv_esc", detail={}, confidence_contribution=0.35)
    assert item.source == "auditd_host"


def test_mitre_mapping_rejects_unknown_status():
    with pytest.raises(ValueError):
        MitreMapping(id="T1110", name="Brute Force", status="MAYBE")


def test_mitre_mapping_accepts_known_status():
    mapping = MitreMapping(id="T1110", name="Brute Force", status="CONFIRMED", evidence_ref=[0])
    assert mapping.status == "CONFIRMED"


def test_policy_decision_rejects_unknown_decision():
    with pytest.raises(ValueError):
        PolicyDecision(decision="AUTO_BLOCK", rationale="x", evaluated_at="now")


def test_verdict_rejects_unknown_status():
    with pytest.raises(ValueError):
        Verdict(
            verdict_id="v1",
            alert_name="a",
            created_at="t",
            status="WEIRD",
            iterations_used=0,
            max_iterations=5,
            tool_transcript=[],
            evidence=[],
            confidence_score=0.0,
            confidence_breakdown=[],
            mitre_techniques=[],
            llm_reasoning_narrative="",
            policy_decision=None,
        )


def test_verdict_to_dict_round_trips_nested_dataclasses():
    verdict = Verdict(
        verdict_id="v1",
        alert_name="Test Alert",
        created_at="2026-09-15T00:00:00Z",
        status="CONCLUDED",
        iterations_used=1,
        max_iterations=5,
        tool_transcript=[],
        evidence=[EvidenceItem(source="auditd_host", tag="priv_esc", detail={}, confidence_contribution=0.35)],
        confidence_score=0.35,
        confidence_breakdown=[],
        mitre_techniques=[MitreMapping(id="T1548", name="Priv Esc", status="CONFIRMED", evidence_ref=[0])],
        llm_reasoning_narrative="test narrative",
        policy_decision=PolicyDecision(decision="RECOMMEND", rationale="x", evaluated_at="now"),
    )
    as_dict = verdict.to_dict()
    assert as_dict["evidence"][0]["source"] == "auditd_host"
    assert as_dict["mitre_techniques"][0]["status"] == "CONFIRMED"
    assert as_dict["policy_decision"]["decision"] == "RECOMMEND"
