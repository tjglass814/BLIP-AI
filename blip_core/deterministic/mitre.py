"""
BLIP-AI Core — MITRE ATT&CK Mapping
====================================
Deterministically maps evidence tags to MITRE ATT&CK techniques. The
mapping table below is ported from the technique IDs already declared
in playbooks/brute_force.py, playbooks/privilege_escalation.py,
playbooks/network_recon.py, and playbooks/persistence.py — this module
doesn't introduce any new techniques, it just gives the agentic loop a
fixed vocabulary of evidence tags to attach to those same IDs.

Each tag maps to one or more techniques with a fixed status:
CONFIRMED for tags representing direct, hard-to-spoof evidence (e.g.
kernel-level euid=0, a raw log line showing a key file was modified),
SUSPECTED for tags representing behavioral/heuristic signals that are
consistent with, but do not on their own prove, that technique.
"""

from typing import Dict, List

from blip_core.verdict.schema import EvidenceItem, MitreMapping

_STATUS_RANK = {"SUSPECTED": 0, "CONFIRMED": 1}

# tag -> list of (technique_id, technique_name, status)
TAG_TECHNIQUE_MAP: Dict[str, List[tuple]] = {
    "network_reconnaissance": [
        ("T1046", "Network Service Discovery", "CONFIRMED"),
    ],
    "port_scan": [
        ("T1046", "Network Service Discovery", "CONFIRMED"),
    ],
    "ssh_brute_force": [
        ("T1110", "Brute Force", "CONFIRMED"),
        ("T1078", "Valid Accounts", "SUSPECTED"),
        ("T1021.004", "Remote Services: SSH", "SUSPECTED"),
    ],
    "privilege_escalation_confirmed": [
        ("T1548", "Abuse Elevation Control Mechanism", "CONFIRMED"),
    ],
    "suid_enumeration": [
        ("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", "SUSPECTED"),
    ],
    "sudo_lolbin_execution": [
        ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching Abuse", "SUSPECTED"),
    ],
    "credential_harvesting": [
        ("T1552.001", "Unsecured Credentials: Credentials In Files", "CONFIRMED"),
    ],
    "log_tampering": [
        ("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", "CONFIRMED"),
    ],
    "backdoor_account_created": [
        ("T1136.001", "Create Account: Local Account", "CONFIRMED"),
    ],
    "ingress_tool_transfer": [
        ("T1105", "Ingress Tool Transfer", "SUSPECTED"),
    ],
    "persistence_ssh_key": [
        ("T1098.004", "Account Manipulation: SSH Authorized Keys", "CONFIRMED"),
    ],
    "persistence_cron": [
        ("T1053.003", "Scheduled Task/Job: Cron", "CONFIRMED"),
    ],
    "persistence_systemd": [
        ("T1543.002", "Create or Modify System Process: Systemd Service", "CONFIRMED"),
    ],
    "persistence_bashrc": [
        ("T1546.004", "Event Triggered Execution: Unix Shell Configuration Modification", "CONFIRMED"),
    ],
}


class UnknownEvidenceTag(Exception):
    """Raised when an evidence item's tag has no MITRE mapping defined."""


def map_evidence_to_techniques(evidence: List[EvidenceItem]) -> List[MitreMapping]:
    """
    Map a Verdict's evidence list to MITRE techniques.

    Every evidence tag must appear in TAG_TECHNIQUE_MAP — an unmapped
    tag raises rather than being silently dropped, since a technique
    BLIP-AI can't name is a gap in this table, not a reason to omit it
    from the verdict. When multiple evidence items map to the same
    technique, their evidence_ref indices are merged and the higher of
    CONFIRMED/SUSPECTED status wins.
    """
    merged: Dict[str, MitreMapping] = {}

    for index, item in enumerate(evidence):
        if item.tag not in TAG_TECHNIQUE_MAP:
            raise UnknownEvidenceTag(
                f"No MITRE mapping defined for evidence tag '{item.tag}' — "
                f"add it to TAG_TECHNIQUE_MAP in blip_core/deterministic/mitre.py"
            )

        for technique_id, name, status in TAG_TECHNIQUE_MAP[item.tag]:
            if technique_id not in merged:
                merged[technique_id] = MitreMapping(
                    id=technique_id, name=name, status=status, evidence_ref=[index]
                )
                continue

            existing = merged[technique_id]
            existing.evidence_ref.append(index)
            if _STATUS_RANK[status] > _STATUS_RANK[existing.status]:
                existing.status = status

    return [merged[technique_id] for technique_id in sorted(merged)]
