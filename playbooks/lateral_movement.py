"""
BLIP-AI Playbook — Lateral Movement Detection
Project 8 — Domain 1: Linux and SIEM

Investigates lateral movement activity:
- Outbound SSH pivot (PROCTITLE decode + SYSCALL join)
- Internal network scanning (EXECVE argument extraction)
- Host-scoped combined behavioral correlation

Architectural note: EXECVE records lack auid/ses/tty fields.
Combined score uses host-scoped correlation rather than session-scoped.
V2 improvement: use transaction event_id to link EXECVE to SYSCALL.

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-60m", latest: str = "now") -> dict:
    """
    Run the lateral movement investigation playbook.

    Args:
        alert_name: Name of the triggered Splunk alert
        earliest: Search window start (default -60m)
        latest: Search window end (default now)

    Returns:
        dict: Structured evidence for Claude analyst
    """

    connector = SplunkConnector()
    evidence = {
        "playbook": "lateral_movement",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Outbound SSH Pivot
    # PROCTITLE decode to extract target hosts from SSH commands
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=PROCTITLE"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
| where match(decoded,"^(ssh|scp|sftp)\\s")
| rex field=decoded "(?:ssh|scp|sftp)\\s+(?:-[^\\s]+\\s+)*?(?:(?:[^@\\s]+)@)?(?P<target_host>[^\\s:]+)"
| eval internal_target=if(
    match(target_host,"^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)"),
    1, 0
)
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=SYSCALL"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "auid=(?P<auid>\\d+)"
    | rex field=_raw "ses=(?P<ses>\\d+)"
    | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
    | rex field=_raw "tty=(?P<tty>\\S+)"
    | rex field=_raw "success=(?P<success>\\w+)"
    | where comm IN ("ssh","scp","sftp")
    | where auid!=4294967295
    | where tty!="(none)"
    | where success="yes" OR success="1"
    | table event_id auid ses comm tty success
]
| where isnotnull(auid)
| stats
    count as connection_attempts
    dc(target_host) as unique_targets
    values(comm) as tools_used
    values(decoded) as commands_run
    values(target_host) as target_hosts
    max(internal_target) as internal_target
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    unique_targets>=3, 0.95,
    unique_targets=2, 0.90,
    internal_target=1 AND connection_attempts>=3, 0.95,
    internal_target=1, 0.85,
    isnotnull(target_hosts), 0.70,
    true(), 0.60
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host connection_attempts unique_targets tools_used target_hosts commands_run first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["outbound_ssh_pivot"] = {
        "description": "SSH/SCP/SFTP executions from interactive sessions targeting internal hosts",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.935,
        "mitre": ["T1021.004"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with outbound SSH pivot activity. "
            "Compromised host initiating SSH connections to internal targets."
            if len(check1_results) > 0
            else "No outbound SSH pivot activity detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Internal Network Scanning
    # EXECVE record argument extraction for scan tool detection
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=EXECVE"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| rex field=_raw "a0=\\"(?P<a0>[^\\"]+)\\""
| rex field=_raw "a1=\\"(?P<a1>[^\\"]+)\\""
| rex field=_raw "a2=\\"(?P<a2>[^\\"]+)\\""
| where a0 IN ("nmap","masscan","arp-scan","netdiscover")
| eval scan_target=coalesce(a2,a1)
| eval internal_target=if(
    match(scan_target,"^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)"),
    1, 0
)
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=SYSCALL"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "auid=(?P<auid>\\d+)"
    | rex field=_raw "ses=(?P<ses>\\d+)"
    | rex field=_raw "tty=(?P<tty>\\S+)"
    | rex field=_raw "success=(?P<success>\\w+)"
    | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
    | where auid!=4294967295
    | where success="yes" OR success="1"
    | table event_id auid ses tty comm success
]
| where isnotnull(auid)
| stats
    count as scan_count
    values(a0) as tools_used
    values(scan_target) as targets_scanned
    dc(scan_target) as unique_targets
    max(internal_target) as internal_target
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval evidence_weight=case(
    internal_target=1 AND unique_targets>=2, 0.95,
    internal_target=1, 0.85,
    unique_targets>=2, 0.75,
    isnotnull(targets_scanned), 0.70,
    true(), 0.60
)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host scan_count unique_targets tools_used targets_scanned first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["internal_network_scan"] = {
        "description": "Network scanning tools targeting internal RFC1918 subnets from this host",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "HIGH" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.85,
        "mitre": ["T1046"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with internal network scanning. "
            "Compromised host mapping internal network for lateral movement targets."
            if len(check2_results) > 0
            else "No internal network scanning detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Host-Scoped Lateral Movement Score
    # Host-scoped correlation — EXECVE records lack session context
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("type=SYSCALL" OR "type=EXECVE")
| rex field=_raw "type=(?P<record_type>\\w+)"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "a0=\\"(?P<a0>[^\\"]+)\\""
| rex field=_raw "a2=\\"(?P<a2>[^\\"]+)\\""
| eval ssh_pivot=if(record_type="SYSCALL" AND comm IN ("ssh","scp","sftp") AND auid!=4294967295 AND tty!="(none)" AND (success="yes" OR success="1"), 1, 0)
| eval internal_scan=if(record_type="EXECVE" AND a0 IN ("nmap","masscan","arp-scan","netdiscover") AND match(a2,"^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)"), 1, 0)
| where ssh_pivot=1 OR internal_scan=1
| stats
    sum(ssh_pivot) as ssh_pivot_count
    sum(internal_scan) as scan_count
    min(_time) as first_seen
    max(_time) as last_seen
    by host
| where ssh_pivot_count > 0 AND scan_count > 0
| eval combined_confidence=0.935
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence host ssh_pivot_count scan_count first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["combined_lateral_movement"] = {
        "description": "Host-scoped correlation of SSH pivot + internal scanning within 60-minute window",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1021.004", "T1046", "T1570"],
        "architectural_note": "EXECVE records lack auid/ses/tty — correlation is host-scoped. V2: use transaction event_id.",
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} host(s) with combined lateral movement pattern. "
            "SSH pivoting AND internal scanning on same host confirms active lateral movement."
            if len(check3_results) > 0
            else "No combined lateral movement pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — SSH Target IOC Extraction
    # Extract destination IPs for network blocking
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=PROCTITLE"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
| where match(decoded,"^(ssh|scp|sftp)\\s")
| rex field=decoded "(?:ssh|scp|sftp)\\s+(?:-[^\\s]+\\s+)*?(?:(?:[^@\\s]+)@)?(?P<target_ip>[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}})"
| where isnotnull(target_ip)
| stats
    count as connection_count
    values(decoded) as full_commands
    by target_ip
| eval ioc_type="lateral_movement_target"
| sort -connection_count
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["ssh_target_iocs"] = {
        "description": "Destination IPs from SSH pivot commands — actionable network IOCs",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"CONFIRMED — {len(check4_results)} unique target IP(s) identified from SSH pivot commands. "
            "Use for network segmentation and firewall rules."
            if len(check4_results) > 0
            else "No SSH target IPs extracted."
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
            "CRITICAL" if len(confirmed_checks) >= 2
            else "HIGH" if len(confirmed_checks) == 1
            else "LOW"
        ),
        "recommended_actions": _get_recommendations(evidence["checks"]),
        "kill_chain_phase": _get_kill_chain(evidence["checks"])
    }

    return evidence


def _get_recommendations(checks: dict) -> list:
    """Generate priority actions based on confirmed checks."""
    actions = []

    if checks.get("combined_lateral_movement", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Isolate affected host from internal network — active lateral movement confirmed")
        actions.append("IMMEDIATE: Block outbound SSH from this host at OPNsense firewall")

    if checks.get("ssh_target_iocs", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Review all destination IPs from SSH commands — block at firewall if unauthorized")
        actions.append("SHORT TERM: Check destination hosts for signs of compromise")

    if checks.get("outbound_ssh_pivot", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Audit SSH authorized_keys on all internal hosts")
        actions.append("SHORT TERM: Check for new user accounts on destination hosts")
        actions.append("REMEDIATION: Rotate all SSH keypairs in the environment")

    if checks.get("internal_network_scan", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Review scan targets for subsequent connection attempts")
        actions.append("REMEDIATION: Implement network segmentation to limit internal visibility")

    if not actions:
        actions.append("Continue monitoring — no confirmed lateral movement detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    """Map confirmed activity to Lockheed Martin Kill Chain phases."""
    phases = []

    if checks.get("internal_network_scan", {}).get("result_count", 0) > 0:
        phases.append("Reconnaissance (internal) — mapping reachable hosts before lateral movement")

    if checks.get("outbound_ssh_pivot", {}).get("result_count", 0) > 0:
        phases.append("Lateral Movement — compromised host initiating SSH connections to internal targets")

    if checks.get("combined_lateral_movement", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — active multi-host compromise in progress")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Lateral Movement Behavioral Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
