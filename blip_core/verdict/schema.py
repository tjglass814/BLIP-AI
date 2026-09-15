"""
BLIP-AI Core — Verdict Schema
=============================
The structured audit record every investigation returns: the full tool
transcript, tagged evidence by source, a deterministically-computed
confidence score, MITRE mapping, the LLM's narrative, and the policy
decision. This is the seed of the future "why?" explainability view —
nothing here is free text without a corresponding structured field.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

EVIDENCE_SOURCES = ("zeek_behavioral", "auditd_host", "suricata_signature", "opnsense_network")
MITRE_STATUSES = ("CONFIRMED", "SUSPECTED", "NOT_DETECTED")
VERDICT_STATUSES = ("CONCLUDED", "MAX_ITERATIONS_REACHED", "ERROR")
POLICY_DECISIONS = ("RECOMMEND",)  # the only legal value in v1 — see deterministic/policy.py


@dataclass
class ToolCall:
    seq: int
    tool_name: str
    input: Dict[str, Any]
    output_summary: Dict[str, Any]
    risk_level: str
    llm_rationale: str
    timestamp: str


@dataclass
class EvidenceItem:
    source: str  # one of EVIDENCE_SOURCES
    tag: str
    detail: Dict[str, Any]
    confidence_contribution: float

    def __post_init__(self):
        if self.source not in EVIDENCE_SOURCES:
            raise ValueError(
                f"Unknown evidence source '{self.source}' — must be one of {EVIDENCE_SOURCES}"
            )


@dataclass
class ConfidenceFactor:
    factor: str
    weight: float
    applied: float
    reason: str


@dataclass
class MitreMapping:
    id: str
    name: str
    status: str  # one of MITRE_STATUSES
    evidence_ref: List[int] = field(default_factory=list)

    def __post_init__(self):
        if self.status not in MITRE_STATUSES:
            raise ValueError(
                f"Unknown MITRE status '{self.status}' — must be one of {MITRE_STATUSES}"
            )


@dataclass
class PolicyDecision:
    decision: str  # one of POLICY_DECISIONS
    rationale: str
    evaluated_at: str

    def __post_init__(self):
        if self.decision not in POLICY_DECISIONS:
            raise ValueError(
                f"Unknown policy decision '{self.decision}' — must be one of {POLICY_DECISIONS}"
            )


@dataclass
class Verdict:
    verdict_id: str
    alert_name: str
    created_at: str
    status: str  # one of VERDICT_STATUSES
    iterations_used: int
    max_iterations: int
    tool_transcript: List[ToolCall]
    evidence: List[EvidenceItem]
    confidence_score: float
    confidence_breakdown: List[ConfidenceFactor]
    mitre_techniques: List[MitreMapping]
    llm_reasoning_narrative: str
    policy_decision: Any  # PolicyDecision, or None before policy has run

    def __post_init__(self):
        if self.status not in VERDICT_STATUSES:
            raise ValueError(
                f"Unknown verdict status '{self.status}' — must be one of {VERDICT_STATUSES}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
