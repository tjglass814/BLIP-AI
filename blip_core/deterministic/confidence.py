"""
BLIP-AI Core — Confidence Scoring
=================================
Pure functions computing a Verdict's confidence score directly from its
evidence list — never from any number the LLM produced.

The scoring model is independent-source corroboration, not a flat
additive sum: the same total evidence weight scores meaningfully higher
when it comes from multiple distinct telemetry sources (zeek_behavioral
+ auditd_host + suricata_signature, say) than when it all comes from a
single source, because agreement between independent detection
technologies is stronger signal than more alerts from one sensor that
could itself be wrong, misconfigured, or evaded.

Verdict tier cutoffs (0.90 / 0.70 / 0.50 / 0.30) and their labels are
ported unchanged from investigation_engine.py's determine_verdict().
"""

from collections import defaultdict
from typing import List, Tuple

from blip_core.verdict.schema import ConfidenceFactor, EvidenceItem

# No source, however much evidence it produces on its own, contributes
# more than this to the raw base before corroboration is considered.
EVIDENCE_CAP = 1.0

# Multiplier applied to the raw evidence total based on how many
# distinct sources contributed non-zero evidence. Deliberately
# superlinear: each additional independent source is worth more than
# an additional item from a source already represented would be.
CORROBORATION_MULTIPLIERS = {
    1: 1.00,
    2: 1.15,
    3: 1.30,
    4: 1.40,  # all four currently-defined evidence sources agree
}

# Ported from investigation_engine.py's determine_verdict().
TIER_CUTOFFS = (
    (0.90, "CRITICAL — Confirmed attack chain"),
    (0.70, "HIGH — Strong indicators of compromise"),
    (0.50, "MEDIUM — Suspicious activity detected"),
    (0.30, "LOW — Anomalous activity worth monitoring"),
)
INFORMATIONAL_TIER = "INFORMATIONAL — No significant threat detected"


def compute_confidence(evidence: List[EvidenceItem]) -> Tuple[float, List[ConfidenceFactor]]:
    """
    Compute a confidence score and its explanatory breakdown from a
    Verdict's evidence list.

    Returns (score, breakdown): score is rounded to 2 decimals and
    clamped to [0.0, 1.0]; breakdown is a list of ConfidenceFactor rows
    — one per contributing source, plus rows documenting the
    corroboration multiplier and any capping, so every score traces
    back to a specific, inspectable cause.
    """
    if not evidence:
        return 0.0, [
            ConfidenceFactor(
                factor="no_evidence",
                weight=0.0,
                applied=0.0,
                reason="No evidence was collected — confidence defaults to 0.0.",
            )
        ]

    items_by_source = defaultdict(list)
    for item in evidence:
        items_by_source[item.source].append(item)

    breakdown: List[ConfidenceFactor] = []
    raw_total = 0.0
    for source in sorted(items_by_source):
        items = items_by_source[source]
        source_total = sum(item.confidence_contribution for item in items)
        raw_total += source_total
        tags = ", ".join(sorted({item.tag for item in items}))
        breakdown.append(
            ConfidenceFactor(
                factor=source,
                weight=round(source_total, 4),
                applied=round(source_total, 4),
                reason=f"{len(items)} evidence item(s) ({tags}) from {source}",
            )
        )

    base = min(raw_total, EVIDENCE_CAP)
    if raw_total > EVIDENCE_CAP:
        breakdown.append(
            ConfidenceFactor(
                factor="raw_evidence_capped",
                weight=EVIDENCE_CAP,
                applied=round(EVIDENCE_CAP - raw_total, 4),
                reason=(
                    f"Raw evidence weight {round(raw_total, 2)} exceeded the "
                    f"{EVIDENCE_CAP} single-pass cap before corroboration was applied."
                ),
            )
        )

    n_sources = len(items_by_source)
    multiplier = CORROBORATION_MULTIPLIERS.get(min(n_sources, 4), 1.00)
    pre_final = base * multiplier

    if n_sources > 1:
        breakdown.append(
            ConfidenceFactor(
                factor="independent_source_corroboration",
                weight=n_sources,
                applied=round(min(pre_final, EVIDENCE_CAP) - base, 4),
                reason=(
                    f"Evidence corroborated across {n_sources} independent sources "
                    f"({', '.join(sorted(items_by_source))}) — corroboration multiplier "
                    f"x{multiplier:.2f} applied to the {round(base, 2)} base evidence weight."
                ),
            )
        )

    if pre_final > EVIDENCE_CAP:
        breakdown.append(
            ConfidenceFactor(
                factor="corroboration_capped",
                weight=EVIDENCE_CAP,
                applied=round(EVIDENCE_CAP - pre_final, 4),
                reason=(
                    f"Corroboration-weighted score {round(pre_final, 2)} exceeded 1.0 "
                    f"and was capped."
                ),
            )
        )

    final_score = min(pre_final, EVIDENCE_CAP)
    return round(final_score, 2), breakdown


def verdict_tier(score: float) -> str:
    """Map a confidence score to its verdict tier label."""
    for cutoff, label in TIER_CUTOFFS:
        if score >= cutoff:
            return label
    return INFORMATIONAL_TIER
