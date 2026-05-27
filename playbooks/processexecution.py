"""
BLIP-AI Playbook — Process Execution Analytics
Project 8 — Domain 1: Linux and SIEM

Investigates process execution anomalies:
- Service account shell spawns (svc_shell_spawn)
- Shell binary execution patterns (shell_spawn)
- Post-exploitation recon chains (proc_exec)

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime, timedelta

# Add parent directory to path for splunk_connector import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-60m", latest: str = "now") -> dict:
    """
    Run the process execution investigation playbook.

    Args:
        alert_name: Name of the triggered Splunk alert
        earliest: Search window start (default -60m)
        latest: Search window end (default now)

    Returns:
        dict: Structured evidence for Claude analyst
    """

    connector = SplunkConnector()
    evidence = {
        "playbook": "process_execution",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Service Account Shell Spawns
    # Look for shells executed under uid=33 (www-data) with real TTY
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"svc_shell_spawn" "type=SYSCALL"
| rex field=_raw "ppid=(?P<ppid>\\d+)"
| rex field=_raw " pid=(?P<pid>\\d+)"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| where success="yes" OR success="1"
| where uid=33
| where tty!="(none)"
| where match(exe,"/(bash|sh|dash|zsh|ksh)$")
| eval uid_resolved="www-data"
| table _time uid uid_resolved auid ses ppid pid comm exe tty
| sort _time
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["service_account_shell_spawn"] = {
        "description": "Interactive shell processes spawned under www-data (uid=33)",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1059.004", "T1190"],
        "interpretation": (
            "CONFIRMED — www-data spawned interactive shell. Web shell exploitation pattern."
            if len(check1_results) > 0
            else "No service account shell spawns detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Post-Exploitation Recon Chain
    # Detect 3+ distinct recon commands within 60-second window
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"proc_exec" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(id|whoami|hostname|uname|ps|netstat|cat|find|getent|w|who|last|ifconfig|ip|arp|ss)$")
| where NOT match(exe,"^/opt/splunk")
| eval recon_window=floor(_time/60)
| stats
    dc(comm) as distinct_commands
    values(comm) as commands_run
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host recon_window
| where distinct_commands >= 3
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort first_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["recon_chain"] = {
        "description": "3+ distinct recon commands within 60-second window per session",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "HIGH" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.75,
        "mitre": ["T1082", "T1033", "T1057"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} recon chain window(s) detected. "
            "Post-exploitation enumeration pattern."
            if len(check2_results) > 0
            else "No recon chain activity detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Behavioral Score
    # Correlate both signals within same session
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("svc_shell_spawn" OR "proc_exec") AND "type=SYSCALL"
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
    key="svc_shell_spawn" AND uid=33 AND match(exe,"/(bash|sh|dash|zsh|ksh)$"), "service_shell_spawn",
    key="proc_exec" AND match(comm,"^(id|whoami|hostname|uname|ps|netstat|cat|find|getent|w|who|last|ifconfig|ip|arp|ss)$") AND NOT match(exe,"^/opt/splunk"), "recon_command",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(eval(case(technique="service_shell_spawn",0.90,technique="recon_command",0.75,true(),0))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.25, 2), 1.0)
| eval severity=case(combined_confidence>=0.90,"CRITICAL",combined_confidence>=0.75,"HIGH",true(),"MEDIUM")
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort -combined_confidence
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["combined_behavioral_score"] = {
        "description": "Multi-signal session correlation: shell spawn + recon chain",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1059.004", "T1190", "T1082", "T1033", "T1057"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with multi-signal behavioral match. "
            "Service account shell spawn AND recon chain in same session."
            if len(check3_results) > 0
            else "No multi-signal sessions detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Recent Shell Spawn Timeline
    # Full chronological view of svc_shell_spawn events for IR timeline
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"svc_shell_spawn" "type=SYSCALL"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "ppid=(?P<ppid>\\d+)"
| rex field=_raw " pid=(?P<pid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| where success="yes" OR success="1"
| where uid=33
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table timestamp uid auid ses ppid pid comm exe tty
| sort timestamp
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["shell_spawn_timeline"] = {
        "description": "Chronological timeline of service account shell spawn events",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Timeline contains {len(check4_results)} shell spawn event(s) under www-data. "
            "Use for IR attack chain reconstruction."
            if len(check4_results) > 0
            else "No shell spawn events in timeline window."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 5 — IOC Extraction
    # Pull destination IPs from /dev/tcp payloads in PROCTITLE records
    # ------------------------------------------------------------------ #
    check5_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"svc_shell_spawn"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1"))
| rex field=decoded "/dev/tcp/(?P<dest_ip>[\\d\\.]+)/(?P<dest_port>\\d+)"
| where isnotnull(dest_ip)
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| stats
    values(dest_ip) as destination_ips
    values(dest_port) as destination_ports
    count as connection_attempts
    by auid ses host
| eval ioc_type="C2_IP"
"""

    check5_results = connector.search(check5_query)
    evidence["checks"]["ioc_extraction"] = {
        "description": "C2 destination IPs extracted from reverse shell PROCTITLE payloads",
        "query": check5_query.strip(),
        "result_count": len(check5_results),
        "results": check5_results,
        "severity": "CRITICAL" if len(check5_results) > 0 else "NONE",
        "mitre": ["T1071"],
        "interpretation": (
            f"CONFIRMED — {len(check5_results)} C2 connection(s) identified. "
            "Destination IPs are actionable IOCs for network blocking."
            if len(check5_results) > 0
            else "No C2 IPs extracted from PROCTITLE records."
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

    if checks.get("ioc_extraction", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Block destination IPs at OPNsense firewall")
        actions.append("IMMEDIATE: Isolate affected host from network")

    if checks.get("service_account_shell_spawn", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Identify and disable web shell on server")
        actions.append("SHORT TERM: Review web application logs for initial access vector")
        actions.append("SHORT TERM: Audit www-data accessible files and writable paths")

    if checks.get("recon_chain", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Review all commands run in affected session")
        actions.append("SHORT TERM: Check for any files created or modified post-recon")

    if checks.get("combined_behavioral_score", {}).get("result_count", 0) > 0:
        actions.append("REMEDIATION: Full forensic review of web application")
        actions.append("REMEDIATION: Rotate all credentials accessible from compromised account")
        actions.append("REMEDIATION: Review web server configuration and uploaded file restrictions")

    if not actions:
        actions.append("Continue monitoring — no confirmed malicious activity detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    """Map confirmed activity to Lockheed Martin Kill Chain phases."""
    phases = []

    if checks.get("service_account_shell_spawn", {}).get("result_count", 0) > 0:
        phases.append("Exploitation — web server process spawned interactive shell")
        phases.append("Installation — attacker established interactive session")

    if checks.get("recon_chain", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — post-exploitation system enumeration")

    if checks.get("ioc_extraction", {}).get("result_count", 0) > 0:
        phases.append("Command and Control — outbound reverse shell connection established")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    # Allow direct execution for testing
    alert = sys.argv[1] if len(sys.argv) > 1 else "Service Account Shell Spawn Detected"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
