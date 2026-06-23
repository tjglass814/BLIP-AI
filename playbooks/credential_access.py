"""
BLIP-AI Playbook — Credential Access and Privilege Abuse Detection
Project 14 — Domain 1: Linux and SIEM

Investigates credential access and privilege abuse:
- Credential file and auth log harvesting (shadow_access + auth_log_read keys)
- Privileged execution by non-root user (proc_exec + euid=0 + auid!=0)
- Combined session-scoped behavioral correlation

Key architectural lesson:
- Use auid (audit login UID) not uid to identify non-root users gaining root
- uid=0 AND euid=0 is common in sudo child processes — uid!=0 misses most cases
- auid persists from original login through all privilege escalation

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
        "playbook": "credential_access",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Credential File and Auth Log Harvesting
    # shadow_access + auth_log_read keys with PATH validation
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("shadow_access" OR "auth_log_read") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where NOT match(comm,"^(sudo|cron|tailreader|splunkd|sshd|journalctl|logrotate|rsyslogd)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"(^/etc/shadow$|^/var/log/auth\\.log$|^/var/log/secure$|/\\.ssh/)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval target_type=case(
    match(mvjoin(filepath," "),"^/etc/shadow"), "shadow_file",
    match(mvjoin(filepath," "),"/\\.ssh/"), "ssh_keys",
    match(mvjoin(filepath," "),"auth\\.log|/var/log/secure"), "auth_log",
    true(), "credential_file"
)
| eval evidence_weight=case(
    target_type="shadow_file", 0.95,
    target_type="ssh_keys", 0.90,
    target_type="auth_log", 0.70,
    true(), 0.65
)
| stats
    count as access_count
    values(comm) as tools_used
    values(filepath) as files_accessed
    values(target_type) as target_types
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host access_count tools_used target_types files_accessed first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["credential_harvesting"] = {
        "description": "Interactive reads of /etc/shadow, SSH keys, and auth logs",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.95,
        "mitre": ["T1003.008", "T1552.004"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with credential file access. "
            "Review files_accessed for shadow file or SSH key harvesting."
            if len(check1_results) > 0
            else "No credential file harvesting detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Privileged Execution by Non-Root User
    # proc_exec key — euid=0 with auid!=0 filtering
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"proc_exec" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "euid=(?P<euid>\\d+)"
| rex field=_raw "uid=(?P<uid>\\d+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where auid!=0
| where tty!="(none)"
| where euid=0
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
| eval abuse_type=case(
    match(comm,"^(bash|sh|dash|zsh|fish|su)$"), "shell_spawned_as_root",
    match(comm,"^(vim|vi|nano|less|more)$") AND has_proctitle=1
        AND match(mvjoin(decoded," "),"(^!|:!|os\\.system|exec\\()"), "editor_shell_escape",
    match(comm,"^(python3?|perl|ruby|lua|php)$"), "interpreter_exec_as_root",
    match(comm,"^(find|awk|sed|nmap|curl|wget)$"), "lolbin_exec_as_root",
    match(comm,"^(whoami|id|hostname)$"), "privilege_verification",
    true(), "privileged_exec"
)
| eval evidence_weight=case(
    abuse_type="editor_shell_escape", 0.95,
    abuse_type="interpreter_exec_as_root", 0.90,
    abuse_type="shell_spawned_as_root", 0.85,
    abuse_type="lolbin_exec_as_root", 0.75,
    abuse_type="privilege_verification", 0.75,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(abuse_type) as abuse_types
    values(decoded) as commands_run
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used abuse_types commands_run first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["privileged_execution"] = {
        "description": "Non-root user (auid!=0) gaining root effective UID — sudo abuse and shell escapes",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.95,
        "mitre": ["T1548.003", "T1059"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with privileged execution by non-root user. "
            "Review abuse_types and commands_run for shell spawning, interpreter abuse, or editor escapes."
            if len(check2_results) > 0
            else "No privileged execution by non-root user detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Credential Access and Privilege Abuse Score
    # Session-scoped correlation of all three technique categories
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("shadow_access" OR "auth_log_read" OR "proc_exec") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| rex field=_raw "euid=(?P<euid>\\d+)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where auid!=0
| where tty!="(none)"
| where NOT match(comm,"^(sudo|cron|tailreader|splunkd|sshd|journalctl|logrotate)$")
| eval technique=case(
    key="shadow_access" AND match(comm,"^(cat|grep|python3?|perl|less|more|head|tail)$"),
        "credential_harvesting",
    key="auth_log_read" AND match(comm,"^(cat|grep|less|more|head|tail|awk)$"),
        "auth_log_harvesting",
    key="proc_exec" AND euid=0
        AND match(comm,"^(bash|sh|dash|zsh|fish|su|python3?|perl|vim|vi|whoami|id)$"),
        "privileged_execution",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="credential_harvesting", 0.90,
    technique="auth_log_harvesting", 0.70,
    technique="privileged_execution", 0.85,
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
    evidence["checks"]["combined_credential_privilege"] = {
        "description": "Session-scoped correlation of credential harvesting and privileged execution",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1003.008", "T1552.004", "T1548.003", "T1059", "T1078"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with combined credential access and privilege abuse. "
            "Active credential theft combined with root-level execution confirmed."
            if len(check3_results) > 0
            else "No combined credential access and privilege abuse pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Recent Privileged Session Timeline
    # All euid=0 executions by non-root users for IR triage
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"proc_exec" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "euid=(?P<euid>\\d+)"
| rex field=_raw "tty=(?P<tty>\\S+)"
| where euid=0
| where auid!=4294967295
| where auid!=0
| where tty!="(none)"
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S")
| stats
    count as exec_count
    values(comm) as commands
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| sort -exec_count
| head 10
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid ses host exec_count commands first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["privileged_session_timeline"] = {
        "description": "Top 10 sessions by privileged execution count — IR triage",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Timeline: {len(check4_results)} session(s) with privileged execution activity. "
            "Review commands column for shell spawning, interpreter abuse, or credential access tools."
            if len(check4_results) > 0
            else "No privileged execution sessions in window."
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
            "CRITICAL" if len(confirmed_checks) >= 2
            else "HIGH" if len(confirmed_checks) == 1
            else "LOW"
        ),
        "recommended_actions": _get_recommendations(evidence["checks"]),
        "kill_chain_phase": _get_kill_chain(evidence["checks"])
    }

    return evidence


def _get_recommendations(checks: dict) -> list:
    actions = []

    if checks.get("combined_credential_privilege", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Assume credentials compromised — initiate password rotation")
        actions.append("IMMEDIATE: Review session history for data access and exfiltration indicators")

    if checks.get("credential_harvesting", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Rotate all passwords on this system — shadow file may have been read")
        actions.append("IMMEDIATE: Check SSH authorized_keys for unauthorized entries on all accounts")
        actions.append("SHORT TERM: Force password reset for all accounts with hashes in /etc/shadow")

    if checks.get("privileged_execution", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Review sudo configuration — consider restricting NOPASSWD grants")
        actions.append("SHORT TERM: Audit all files accessed during privileged session")
        actions.append("REMEDIATION: Review and tighten sudoers configuration")

    if not actions:
        actions.append("Continue monitoring — no confirmed credential access or privilege abuse detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("credential_harvesting", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — credential file access, password hashes or keys may be stolen")

    if checks.get("privileged_execution", {}).get("result_count", 0) > 0:
        phases.append("Privilege Escalation — non-root user gained root effective UID")

    if checks.get("combined_credential_privilege", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — combined credential theft and privilege abuse confirms active attack")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Credential Access and Privilege Abuse Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
