"""
BLIP-AI Playbook — Internal Reconnaissance Detection
Project 7 — Domain 1: Linux and SIEM

Investigates internal reconnaissance activity:
- Credential file enumeration (shadow_access, passwd_read, group_read)
- Network discovery (network_config_read, proc_exec network tools)
- Sensitive file hunting (homedir_read PROCTITLE decode)
- Session-scoped multi-signal correlation

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-60m", latest: str = "now") -> dict:
    """
    Run the internal reconnaissance investigation playbook.

    Args:
        alert_name: Name of the triggered Splunk alert
        earliest: Search window start (default -60m)
        latest: Search window end (default now)

    Returns:
        dict: Structured evidence for Claude analyst
    """

    connector = SplunkConnector()
    evidence = {
        "playbook": "internal_recon",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Credential File Enumeration
    # Reads of /etc/shadow, /etc/passwd, /etc/group by inspection tools
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| where success="yes" OR success="1"
| where key IN ("shadow_access","passwd_read","group_read")
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(cat|getent|less|more|strings|grep|awk|head|tail)$")
| eval file_accessed=case(
    key="shadow_access", "/etc/shadow",
    key="passwd_read", "/etc/passwd",
    key="group_read", "/etc/group",
    true(), "unknown"
)
| eval technique_weight=case(
    key="shadow_access", 0.85,
    key="passwd_read", 0.70,
    key="group_read", 0.65,
    true(), 0.50
)
| stats
    dc(file_accessed) as files_accessed
    values(file_accessed) as files
    values(comm) as tools_used
    max(technique_weight) as base_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    files_accessed>=3, min(base_weight + 0.10, 1.0),
    files_accessed=2, min(base_weight + 0.05, 1.0),
    true(), base_weight
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host files_accessed files tools_used first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["credential_file_enumeration"] = {
        "description": "Interactive reads of /etc/shadow, /etc/passwd, /etc/group using inspection tools",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.95,
        "mitre": ["T1003.008", "T1087.001"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with credential file enumeration. "
            "Systematic credential harvesting pattern."
            if len(check1_results) > 0
            else "No credential file enumeration detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Network Discovery Activity
    # Network tool execution + network config file reads
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where (
    (key="proc_exec" AND match(comm,"^(ip|arp|ss|netstat|ifconfig|route|ping|traceroute|dig|nslookup|host|nmap)$") AND NOT match(exe,"^/opt/splunk"))
    OR
    (key="network_config_read" AND match(comm,"^(cat|less|more|grep|strings|awk|head|tail)$"))
)
| eval signal_type=case(
    key="proc_exec", "network_tool_execution",
    key="network_config_read", "network_config_read",
    true(), "unknown"
)
| eval signal_weight=case(
    signal_type="network_tool_execution", 0.60,
    signal_type="network_config_read", 0.55,
    true(), 0.40
)
| stats
    dc(signal_type) as signal_count
    values(signal_type) as signals_detected
    values(comm) as commands_run
    max(signal_weight) as base_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    signal_count>=2, min(base_weight + 0.15, 1.0),
    true(), base_weight
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host signal_count signals_detected commands_run first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["network_discovery"] = {
        "description": "Network topology mapping via tool execution and config file reads",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "HIGH" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.75,
        "mitre": ["T1016", "T1018"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with network discovery activity. "
            "Network topology mapping pattern."
            if len(check2_results) > 0
            else "No network discovery activity detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Sensitive File Discovery
    # PROCTITLE decode to identify SSH key and credential hunting
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=PROCTITLE"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1"))
| eval decoded=lower(decoded)
| where match(decoded,"(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|\\.pem|\\.pfx|\\.p12|\\.kdbx|aws|credentials|\\.env|secret|token|password|credential|vault|\\.ssh)")
| where NOT match(decoded,"auditctl")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=SYSCALL"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "auid=(?P<auid>\\d+)"
    | rex field=_raw "ses=(?P<ses>\\d+)"
    | rex field=_raw "tty=(?P<tty>\\S+)"
    | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
    | rex field=_raw "success=(?P<success>\\w+)"
    | where tty!="(none)"
    | where auid!=4294967295
    | where success="yes" OR success="1"
    | where comm!="auditctl"
    | where match(comm,"^(find|grep|locate|ls|tree|cat|less|more|strings|awk|head|tail)$")
    | table event_id auid ses tty comm success
]
| where isnotnull(auid)
| eval signal_type=case(
    match(decoded,"(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts)"), "ssh_key_hunt",
    match(decoded,"\\.ssh"), "ssh_dir_hunt",
    match(decoded,"(\\.pem|\\.pfx|\\.p12|\\.kdbx)"), "cert_key_hunt",
    match(decoded,"(aws|credentials)"), "cloud_credential_hunt",
    match(decoded,"(\\.env|secret|token|api.key|credential|password|vault)"), "credential_file_hunt",
    true(), "sensitive_file_hunt"
)
| eval tool_weight=case(
    comm="find", 0.15,
    comm="grep", 0.10,
    comm="locate", 0.10,
    comm="ls", 0.05,
    comm="tree", 0.05,
    true(), 0.0
)
| eval signal_weight=case(
    signal_type="ssh_key_hunt", 0.80,
    signal_type="cert_key_hunt", 0.80,
    signal_type="cloud_credential_hunt", 0.80,
    signal_type="ssh_dir_hunt", 0.75,
    signal_type="credential_file_hunt", 0.80,
    true(), 0.60
)
| eval combined_weight=min(signal_weight + tool_weight, 1.0)
| stats
    dc(signal_type) as signal_count
    values(signal_type) as signals_detected
    values(comm) as commands_run
    values(decoded) as search_patterns
    max(combined_weight) as base_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    signal_count>=3, min(base_weight + 0.10, 1.0),
    signal_count=2, min(base_weight + 0.05, 1.0),
    true(), base_weight
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host signal_count signals_detected commands_run search_patterns first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["sensitive_file_discovery"] = {
        "description": "PROCTITLE-decoded credential hunting — SSH keys, .env files, certificates",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "confidence_weight": 1.0,
        "mitre": ["T1552.001", "T1083"],
        "v2_note": "Replace join with transaction event_id for scalability",
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with sensitive file hunting. "
            "SSH key and credential hunting pattern detected via PROCTITLE decode."
            if len(check3_results) > 0
            else "No sensitive file discovery detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Session-Scoped Multi-Signal Correlation
    # Three technique categories correlated within same session
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| eval technique=case(
    key IN ("shadow_access","passwd_read","group_read") AND match(comm,"^(cat|getent|less|more|strings|grep|awk|head|tail)$"), "credential_enumeration",
    key="proc_exec" AND match(comm,"^(ip|arp|ss|netstat|ifconfig|route|ping|traceroute|dig|nslookup|host|nmap)$") AND NOT match(exe,"^/opt/splunk"), "network_tool_execution",
    key="network_config_read" AND match(comm,"^(cat|less|more|grep|strings|awk|head|tail)$"), "network_config_read",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(eval(case(
        technique="credential_enumeration", 0.85,
        technique="network_tool_execution", 0.70,
        technique="network_config_read", 0.60,
        true(), 0.0
    ))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.05, 2), 1.0)
| eval severity=case(combined_confidence>=0.90,"CRITICAL",combined_confidence>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence severity auid ses host technique_count techniques_detected first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["multi_signal_correlation"] = {
        "description": "Session-scoped correlation of credential + network discovery techniques",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "CRITICAL" if len(check4_results) > 0 else "NONE",
        "mitre": ["T1003.008", "T1087.001", "T1016", "T1018"],
        "interpretation": (
            f"CONFIRMED — {len(check4_results)} session(s) with multi-technique recon correlation. "
            "Complete internal reconnaissance operation detected."
            if len(check4_results) > 0
            else "No multi-signal recon correlation detected."
        )
    }

    # ------------------------------------------------------------------ #
    # SUMMARY SCORING
    # ------------------------------------------------------------------ #
    confirmed_checks = [
        k for k, v in evidence["checks"].items()
        if v.get("severity") in ("CRITICAL", "HIGH") and v.get("result_count", 0) > 0
    ]

    evidence["summary"] = {
        "confirmed_checks": confirmed_checks,
        "confirmed_count": len(confirmed_checks),
        "overall_severity": (
            "CRITICAL" if len(confirmed_checks) >= 3
            else "HIGH" if len(confirmed_checks) >= 2
            else "MEDIUM" if len(confirmed_checks) == 1
            else "LOW"
        ),
        "recommended_actions": _get_recommendations(evidence["checks"]),
        "kill_chain_phase": _get_kill_chain(evidence["checks"])
    }

    return evidence


def _get_recommendations(checks: dict) -> list:
    """Generate priority actions based on confirmed checks."""
    actions = []

    if checks.get("multi_signal_correlation", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Isolate affected session — multi-technique recon confirms attacker presence")
        actions.append("IMMEDIATE: Review all commands run in flagged session via ausearch -se <ses>")

    if checks.get("credential_file_enumeration", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Assume credential compromise — rotate all passwords on affected host")
        actions.append("SHORT TERM: Audit /etc/shadow for unauthorized password changes")
        actions.append("SHORT TERM: Check for new user accounts created after enumeration timestamp")

    if checks.get("sensitive_file_discovery", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Audit all SSH authorized_keys files for unauthorized entries")
        actions.append("SHORT TERM: Rotate all SSH keypairs on affected host")
        actions.append("SHORT TERM: Audit .env files for exposed credentials and rotate affected secrets")

    if checks.get("network_discovery", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Review OPNsense logs for unusual outbound connections from this host")
        actions.append("SHORT TERM: Check for lateral movement to other hosts on 10.10.10.x segment")
        actions.append("REMEDIATION: Implement network segmentation to limit blast radius")

    if not actions:
        actions.append("Continue monitoring — no confirmed malicious activity detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    """Map confirmed activity to Lockheed Martin Kill Chain phases."""
    phases = []

    if checks.get("credential_file_enumeration", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — credential harvesting from system files")

    if checks.get("network_discovery", {}).get("result_count", 0) > 0:
        phases.append("Reconnaissance (internal) — network topology mapping post-compromise")

    if checks.get("sensitive_file_discovery", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — SSH key and secret file collection")

    if checks.get("multi_signal_correlation", {}).get("result_count", 0) > 0:
        phases.append("Complete recon phase — systematic environment mapping before lateral movement")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Internal Recon Correlation — Credential and Network Signal Correlation"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
