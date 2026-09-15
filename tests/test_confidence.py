import pytest

from blip_core.deterministic.confidence import (
    INFORMATIONAL_TIER,
    TIER_CUTOFFS,
    compute_confidence,
    verdict_tier,
)
from blip_core.verdict.schema import EvidenceItem


def evidence(source, tag, contribution):
    return EvidenceItem(source=source, tag=tag, detail={}, confidence_contribution=contribution)


def test_no_evidence_scores_zero():
    score, breakdown = compute_confidence([])
    assert score == 0.0
    assert len(breakdown) == 1
    assert breakdown[0].factor == "no_evidence"


def test_single_source_two_items_sums_flat():
    items = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.4),
        evidence("auditd_host", "credential_harvesting", 0.4),
    ]
    score, breakdown = compute_confidence(items)
    assert score == 0.8
    # exactly one source row, no corroboration row for a single source
    assert len(breakdown) == 1
    assert breakdown[0].factor == "auditd_host"


def test_two_sources_score_higher_than_same_total_from_one_source():
    single_source = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.4),
        evidence("auditd_host", "credential_harvesting", 0.4),
    ]
    two_sources = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.4),
        evidence("zeek_behavioral", "lateral_movement_beacon", 0.4),
    ]
    single_score, _ = compute_confidence(single_source)
    multi_score, breakdown = compute_confidence(two_sources)

    assert single_score == 0.8
    assert multi_score == 0.92  # 0.8 base * 1.15 two-source multiplier
    assert multi_score > single_score

    corroboration_rows = [row for row in breakdown if row.factor == "independent_source_corroboration"]
    assert len(corroboration_rows) == 1
    assert corroboration_rows[0].applied == pytest.approx(0.12)


def test_three_independent_sources_saturate_at_cap():
    items = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.3),
        evidence("zeek_behavioral", "lateral_movement_beacon", 0.3),
        evidence("suricata_signature", "known_c2_signature", 0.3),
    ]
    score, breakdown = compute_confidence(items)
    # 0.9 base * 1.30 three-source multiplier = 1.17, capped at 1.0
    assert score == 1.0
    assert any(row.factor == "corroboration_capped" for row in breakdown)


def test_four_sources_use_the_top_multiplier():
    items = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.1),
        evidence("zeek_behavioral", "lateral_movement_beacon", 0.1),
        evidence("suricata_signature", "known_c2_signature", 0.1),
        evidence("opnsense_network", "port_scan", 0.1),
    ]
    score, _ = compute_confidence(items)
    assert score == pytest.approx(0.4 * 1.40, abs=0.001)


def test_raw_total_exceeding_cap_is_flagged():
    items = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.6),
        evidence("auditd_host", "credential_harvesting", 0.6),
    ]
    score, breakdown = compute_confidence(items)
    assert score == 1.0
    assert any(row.factor == "raw_evidence_capped" for row in breakdown)


def test_breakdown_source_row_lists_tags_and_count():
    items = [
        evidence("auditd_host", "privilege_escalation_confirmed", 0.35),
        evidence("auditd_host", "persistence_cron", 0.25),
    ]
    _, breakdown = compute_confidence(items)
    row = breakdown[0]
    assert "2 evidence item(s)" in row.reason
    assert "persistence_cron" in row.reason
    assert "privilege_escalation_confirmed" in row.reason


@pytest.mark.parametrize(
    "score,expected_tier",
    [
        (0.95, "CRITICAL — Confirmed attack chain"),
        (0.90, "CRITICAL — Confirmed attack chain"),
        (0.89, "HIGH — Strong indicators of compromise"),
        (0.70, "HIGH — Strong indicators of compromise"),
        (0.69, "MEDIUM — Suspicious activity detected"),
        (0.50, "MEDIUM — Suspicious activity detected"),
        (0.49, "LOW — Anomalous activity worth monitoring"),
        (0.30, "LOW — Anomalous activity worth monitoring"),
        (0.29, INFORMATIONAL_TIER),
        (0.0, INFORMATIONAL_TIER),
    ],
)
def test_verdict_tier_cutoffs_match_v1_1(score, expected_tier):
    assert verdict_tier(score) == expected_tier


def test_tier_cutoffs_are_the_ported_v1_1_values():
    assert [cutoff for cutoff, _ in TIER_CUTOFFS] == [0.90, 0.70, 0.50, 0.30]
