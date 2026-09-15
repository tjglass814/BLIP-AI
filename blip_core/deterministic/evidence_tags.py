"""
BLIP-AI Core — Evidence Tag Registry
=====================================
The fixed vocabulary of evidence tags the investigation agent may use,
and the deterministic confidence weight tied to each one. The LLM's job
is to identify WHICH tag applies to what it found — it never supplies a
numeric confidence value itself. Confidence math belongs to
deterministic/confidence.py, not the LLM, so the weight lives here
where Python owns it.

network_reconnaissance, ssh_brute_force, privilege_escalation_confirmed,
and port_scan carry the exact confidence_contribution values from
investigation_engine.py's five checks. The rest are finer-grained tags
introduced alongside mitre.py's mapping table, weighted in the same
style as the sub-steps in playbooks/privilege_escalation.py and
playbooks/persistence.py.

Every tag here must also appear in
blip_core/deterministic/mitre.py::TAG_TECHNIQUE_MAP — see
tests/test_evidence_tags.py for the parity check.
"""

from typing import Dict

EVIDENCE_TAGS: Dict[str, dict] = {
    # Ported unchanged from investigation_engine.py's confidence_contribution values.
    "network_reconnaissance": {"weight": 0.20, "allowed_sources": ("opnsense_network", "zeek_behavioral")},
    "ssh_brute_force": {"weight": 0.25, "allowed_sources": ("auditd_host",)},
    "privilege_escalation_confirmed": {"weight": 0.35, "allowed_sources": ("auditd_host",)},
    "port_scan": {"weight": 0.15, "allowed_sources": ("opnsense_network", "zeek_behavioral")},
    "persistence_ssh_key": {"weight": 0.25, "allowed_sources": ("auditd_host",)},
    "persistence_cron": {"weight": 0.25, "allowed_sources": ("auditd_host",)},
    "persistence_systemd": {"weight": 0.25, "allowed_sources": ("auditd_host",)},
    "persistence_bashrc": {"weight": 0.25, "allowed_sources": ("auditd_host",)},
    # Finer-grained tags for mitre.py's mapping table.
    "suid_enumeration": {"weight": 0.10, "allowed_sources": ("auditd_host",)},
    "sudo_lolbin_execution": {"weight": 0.15, "allowed_sources": ("auditd_host",)},
    "credential_harvesting": {"weight": 0.20, "allowed_sources": ("auditd_host",)},
    "log_tampering": {"weight": 0.20, "allowed_sources": ("auditd_host",)},
    "backdoor_account_created": {"weight": 0.20, "allowed_sources": ("auditd_host",)},
    "ingress_tool_transfer": {"weight": 0.10, "allowed_sources": ("auditd_host", "suricata_signature")},
}


def confidence_weight_for(tag: str) -> float:
    """Return the deterministic confidence weight for a known evidence tag."""
    if tag not in EVIDENCE_TAGS:
        raise KeyError(f"No confidence weight defined for evidence tag '{tag}'")
    return EVIDENCE_TAGS[tag]["weight"]
