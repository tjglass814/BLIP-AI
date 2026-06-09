"""
BLIP-AI Playbook — User and Account Manipulation Detection
Project 9 — Domain 1: Linux and SIEM

Investigates account manipulation activity:
- Backdoor user creation and group privilege grants (user_creation key)
- Sudoers file modification (sudoers_change key)
- Session-scoped combined behavioral correlation

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-60m", latest: str = "now") -> dict:
    """
    Run the account manipulation investigation playbook.

    Args:
        alert_name: Name of the triggered Splunk alert
        earliest: Search window start (default -60m)
        latest: Search window end (default now)

    Returns:
        dict: Structured evidence for Claude analyst
    """

    connector = SplunkConnector()
    evidence = {
        "playbook": "account_manipulation",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Backdoor User Account Activity
    # useradd, adduser, usermod with PROCTITLE decode
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"user_creation" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw " uid=(?P<uid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(useradd|adduser|usermod)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PROCTITLE"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
    | table event_id decoded
]
| eval action_type=case(
    match(decoded,"(?i)(sudo|wheel)") AND comm="usermod", "user_added_to_privileged_group",
    comm="useradd" OR comm="adduser", "new_user_created",
    comm="usermod", "user_modified",
    true(), "account_change"
)
| eval evidence_weight=case(
    match(decoded,"(?i)(sudo|wheel)") AND comm="usermod", 0.90,
    comm="useradd" OR comm="adduser", 0.80,
    comm="usermod", 0.70,
    true(), 0.60
)
| stats
    count as event_count
    values(comm) as tools_used
    values(decoded) as commands_run
    values(action_type) as actions
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used actions commands_run first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["backdoor_user_creation"] = {
        "description": "User account creation and privileged group membership changes",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1136.001", "T1098"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with account manipulation. "
            "New user creation or privileged group membership grant detected."
            if len(check1_results) > 0
            else "No backdoor user creation detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Sudoers Modification
    # Writes to /etc/sudoers and /etc/sudoers.d/ excluding sudo reads
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"sudoers_change" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "syscall=(?P<syscall>\\d+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="sudo"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"sudoers")
    | where nametype="NORMAL" OR nametype="CREATE"
    | table event_id filepath nametype
]
| eval action_type=case(
    syscall=263, "sudoers_file_deleted",
    syscall=82, "sudoers_file_renamed",
    match(comm,"^(tee|echo|bash|sh|dash|nano|vim|vi|cp|mv)$"), "sudoers_file_written",
    true(), "sudoers_modified"
)
| eval evidence_weight=case(
    match(comm,"^(tee|echo|bash|sh|dash)$"), 0.90,
    match(comm,"^(nano|vim|vi)$"), 0.80,
    match(comm,"^(cp|mv)$"), 0.75,
    syscall=263, 0.70,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_affected
    values(action_type) as actions
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used files_affected actions first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["sudoers_modification"] = {
        "description": "Writes and deletions to /etc/sudoers and /etc/sudoers.d/ by non-sudo processes",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1548.003"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with sudoers modification. "
            "Direct sudoers write detected — legitimate changes use visudo."
            if len(check2_results) > 0
            else "No sudoers modification detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Session-Scoped Correlation
    # Both account manipulation and sudoers modification in same session
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("user_creation" OR "sudoers_change") "type=SYSCALL"
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
    key="user_creation" AND match(comm,"^(useradd|adduser|usermod)$"), "account_manipulation",
    key="sudoers_change" AND comm!="sudo", "sudoers_modification",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    sum(eval(case(
        technique="account_manipulation", 0.80,
        technique="sudoers_modification", 0.90,
        true(), 0.0
    ))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence auid ses host technique_count techniques_detected first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["combined_account_manipulation"] = {
        "description": "Session-scoped correlation of account creation and sudoers modification",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1136.001", "T1098", "T1548.003", "T1078"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with complete backdoor account sequence. "
            "Account creation AND sudoers modification in same session confirms privilege escalation chain."
            if len(check3_results) > 0
            else "No combined account manipulation pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — New Account Timeline
    # Recent account creations for IR investigation
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"user_creation" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where comm="useradd" OR comm="adduser"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PROCTITLE"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
    | table event_id decoded
]
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table timestamp auid comm decoded
| sort timestamp
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["new_account_timeline"] = {
        "description": "Timeline of new account creation events for IR investigation",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Timeline contains {len(check4_results)} account creation event(s). "
            "Review decoded commands to identify any unexpected usernames or options."
            if len(check4_results) > 0
            else "No account creation events in timeline window."
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

    if checks.get("combined_account_manipulation", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Audit all user accounts — identify and lock any unauthorized accounts")
        actions.append("IMMEDIATE: Review /etc/sudoers and /etc/sudoers.d/ for unauthorized entries")

    if checks.get("backdoor_user_creation", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Run `cat /etc/passwd` and compare against known-good baseline")
        actions.append("SHORT TERM: Check authorized_keys for all new accounts")
        actions.append("SHORT TERM: Review login history for any new account authentications")
        actions.append("REMEDIATION: Remove unauthorized accounts with userdel -r")

    if checks.get("sudoers_modification", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Run `sudo cat /etc/sudoers` and `ls -la /etc/sudoers.d/`")
        actions.append("IMMEDIATE: Remove any unauthorized NOPASSWD entries")
        actions.append("SHORT TERM: Verify sudoers syntax with `visudo -c`")
        actions.append("REMEDIATION: Restore sudoers from known-good backup")

    if not actions:
        actions.append("Continue monitoring — no confirmed account manipulation detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    """Map confirmed activity to Lockheed Martin Kill Chain phases."""
    phases = []

    if checks.get("backdoor_user_creation", {}).get("result_count", 0) > 0:
        phases.append("Installation — backdoor account created for persistent access")

    if checks.get("sudoers_modification", {}).get("result_count", 0) > 0:
        phases.append("Installation — sudo privileges granted for privilege escalation")

    if checks.get("combined_account_manipulation", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — complete backdoor account with root access established")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Account Manipulation Behavioral Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
