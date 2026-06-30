"""
BLIP-AI Playbook — Anti-Detection and Audit Evasion Detection
Project 15 — Domain 1: Linux and SIEM (FINAL PROJECT)

Investigates attacks on the detection infrastructure itself:
- Audit configuration tampering (audit_tampering key + PATH validation)
- Audit rule deletion and evasion (auditctl PROCTITLE classification)
- Combined anti-detection behavioral score

This is the meta-detection — using the SIEM to detect attacks on the SIEM.
If this playbook fires, assume earlier detections may have been suppressed.

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-60m", latest: str = "now") -> dict:
    connector = SplunkConnector()
    evidence = {
        "playbook": "anti_detection",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Audit Configuration Tampering
    # audit_tampering key excluding auditctl, PATH confirms specific files
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"audit_tampering" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="auditctl"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"^/etc/audit/")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval tamper_type=case(
    match(mvjoin(filepath," "),"auditd\\.conf"), "config_file_modified",
    match(mvjoin(filepath," "),"rules\\.d/"), "rules_file_modified",
    true(), "audit_dir_modified"
)
| eval evidence_weight=case(
    tamper_type="rules_file_modified" AND match(comm,"^(rm|python3|perl|bash|sh)$"), 0.95,
    tamper_type="rules_file_modified", 0.90,
    tamper_type="config_file_modified", 0.85,
    true(), 0.75
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_affected
    values(tamper_type) as tamper_types
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used tamper_types files_affected first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["audit_config_tampering"] = {
        "description": "Interactive writes to /etc/audit/ by non-auditctl processes",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.95,
        "mitre": ["T1562.001"],
        "critical_note": "If this fires — check all other BLIP-AI alerts. Rules may have been deleted before this fired.",
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with audit config tampering. "
            "Files written to /etc/audit/ by interactive session — detection infrastructure under attack."
            if len(check1_results) > 0
            else "No audit configuration tampering detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Audit Rule Deletion and Evasion
    # auditctl interactive execution with PROCTITLE evasion classification
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"audit_tampering" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm="auditctl"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PROCTITLE"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
    | stats values(decoded) as decoded by event_id
    | table event_id decoded
]
| eval has_proctitle=if(len(trim(mvjoin(decoded,"")))>0,1,0)
| eval action_type=case(
    has_proctitle=1 AND match(mvjoin(decoded," "),"-e\\s+0\\b"), "auditd_disabled",
    has_proctitle=1 AND match(mvjoin(decoded," ")," -D(\\s|$)"), "delete_all_rules",
    has_proctitle=1 AND match(mvjoin(decoded," ")," -d\\s"), "delete_single_rule",
    has_proctitle=1 AND match(mvjoin(decoded," "),"--backlog-wait-time 0|rate.limit"), "buffer_manipulation",
    has_proctitle=1, "auditctl_interactive",
    true(), "auditctl_unknown"
)
| eval evidence_weight=case(
    action_type="auditd_disabled", 0.98,
    action_type="delete_all_rules", 0.95,
    action_type="delete_single_rule", 0.90,
    action_type="buffer_manipulation", 0.90,
    action_type="auditctl_interactive", 0.75,
    true(), 0.65
)
| stats
    count as event_count
    values(decoded) as commands_run
    values(action_type) as actions
    max(has_proctitle) as has_proctitle
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count actions commands_run first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["audit_rule_evasion"] = {
        "description": "Interactive auditctl executions classified by evasion technique",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.95,
        "mitre": ["T1562.001", "T1562.006"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with interactive auditctl execution. "
            "Review actions field for delete_all_rules or auditd_disabled — highest severity indicators."
            if len(check2_results) > 0
            else "No interactive auditctl evasion detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Anti-Detection Score
    # Multi-technique evasion correlation
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("audit_tampering" OR "forwarder_tamper" OR "log_tamper") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| eval technique=case(
    key="audit_tampering" AND comm="auditctl", "audit_rule_manipulation",
    key="audit_tampering" AND match(comm,"^(tee|sed|cp|rm|touch|python3?|perl|bash|sh)$"), "audit_config_tampering",
    key="forwarder_tamper" AND match(comm,"^(cp|mv|rm|tee|sed|vi|vim|nano)$"), "forwarder_tampering",
    key="log_tamper" AND match(comm,"^(rm|shred|truncate|tee|sed)$"), "log_tampering",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="audit_rule_manipulation", 0.90,
    technique="audit_config_tampering", 0.90,
    technique="forwarder_tampering", 0.85,
    technique="log_tampering", 0.80,
    true(), 0.50
)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(comm) as tools_used
    sum(technique_weight) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| where combined_confidence >= 0.75
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["combined_anti_detection"] = {
        "description": "Multi-technique audit evasion — coordinated attack on detection infrastructure",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1562.001", "T1562.006", "T1070", "T1485"],
        "critical_note": "Multiple evasion techniques in one session means other BLIP-AI detections may have been suppressed. Treat all recent clean alerts as potentially unreliable.",
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with combined anti-detection activity. "
            "CRITICAL: Assume earlier attack phases may have gone undetected. Full IR investigation required."
            if len(check3_results) > 0
            else "No combined anti-detection pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Audit Rule Inventory
    # Current state of loaded rules for IR baseline
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"audit_tampering" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| where auid!=4294967295
| where tty!="(none)"
| stats
    count as total_events
    values(comm) as tools_involved
    dc(comm) as unique_tools
    min(_time) as first_seen
    max(_time) as last_seen
    by auid host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid host total_events unique_tools tools_involved first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["audit_activity_summary"] = {
        "description": "Summary of all audit infrastructure activity for IR timeline",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Audit infrastructure touched by {len(check4_results)} user(s). "
            "Review tools_involved for unauthorized modification tools."
            if len(check4_results) > 0
            else "No audit infrastructure activity detected."
        )
    }

    confirmed_checks = [
        k for k, v in evidence["checks"].items()
        if v.get("severity") in ("CRITICAL", "HIGH") and v.get("result_count", 0) > 0
    ]

    evidence["summary"] = {
        "confirmed_checks": confirmed_checks,
        "confirmed_count": len(confirmed_checks),
        "overall_severity": (
            "CRITICAL" if len(confirmed_checks) >= 1
            else "LOW"
        ),
        "detection_reliability_warning": (
            "WARNING: Anti-detection activity confirmed. Other BLIP-AI playbook results from this session may be unreliable — audit rules may have been deleted before detection fired."
            if len(confirmed_checks) >= 1
            else "Detection infrastructure appears intact."
        ),
        "recommended_actions": _get_recommendations(evidence["checks"]),
        "kill_chain_phase": _get_kill_chain(evidence["checks"])
    }

    return evidence


def _get_recommendations(checks: dict) -> list:
    actions = []

    if checks.get("combined_anti_detection", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Verify current auditd rule count — run auditctl -l | wc -l and compare to baseline of 83")
        actions.append("IMMEDIATE: Check all other BLIP-AI alerts from the past 24 hours — evasion may predate this detection")
        actions.append("IMMEDIATE: Review audit.log for gaps — missing time periods indicate successful rule deletion")

    if checks.get("audit_rule_evasion", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Run auditctl -l to verify rule integrity — compare against /etc/audit/rules.d/blip-ai.rules")
        actions.append("SHORT TERM: If rules were deleted — restore from blip-ai.rules and restart auditd")
        actions.append("SHORT TERM: Consider immutable mode — auditctl -e 2 prevents rule changes without reboot")

    if checks.get("audit_config_tampering", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Review /etc/audit/auditd.conf for unauthorized changes")
        actions.append("SHORT TERM: Compare current config against known-good backup")
        actions.append("REMEDIATION: Restore auditd.conf from backup and restart auditd")

    if not actions:
        actions.append("Detection infrastructure appears intact — continue monitoring")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("audit_config_tampering", {}).get("result_count", 0) > 0:
        phases.append("Defense Evasion — audit configuration modified to reduce detection coverage")

    if checks.get("audit_rule_evasion", {}).get("result_count", 0) > 0:
        phases.append("Defense Evasion — auditctl invoked interactively to manipulate detection rules")

    if checks.get("combined_anti_detection", {}).get("result_count", 0) > 0:
        phases.append("Defense Evasion — coordinated multi-technique attack on SIEM detection infrastructure")

    return phases if phases else ["Detection infrastructure appears intact"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Anti-Detection and Audit Evasion Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
