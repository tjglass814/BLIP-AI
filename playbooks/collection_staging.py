"""
BLIP-AI Playbook — Sensitive File Access and Collection Staging
Project 10 — Domain 1: Linux and SIEM

Investigates collection staging activity:
- Archive creation targeting staging directories (proc_exec + PROCTITLE)
- Sensitive file staging in /tmp, /dev/shm, /var/tmp (staging_write + PATH)
- Session-scoped combined behavioral correlation with evidence separation

Architectural notes:
- PROCTITLE and PATH evidence kept separate through joins
- event_id deduplication prevents row inflation
- Detection 1 excludes events without PROCTITLE to prevent silent degradation

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-60m", latest: str = "now") -> dict:
    """
    Run the collection staging investigation playbook.

    Args:
        alert_name: Name of the triggered Splunk alert
        earliest: Search window start (default -60m)
        latest: Search window end (default now)

    Returns:
        dict: Structured evidence for Claude analyst
    """

    connector = SplunkConnector()
    evidence = {
        "playbook": "collection_staging",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Archive Creation in Staging Directory
    # proc_exec key + PROCTITLE decode for destination validation
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"proc_exec" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(tar|zip|gzip|7z|bzip2)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PROCTITLE"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
    | table event_id decoded
]
| eval has_proctitle=if(isnotnull(decoded),1,0)
| where has_proctitle=1
| eval staging_target=if(
    match(decoded,"(/tmp/|/dev/shm/|/var/tmp/)"),
    1, 0
)
| eval evidence_weight=case(
    staging_target=1 AND match(comm,"^(tar|zip)$"), 0.90,
    staging_target=1, 0.80,
    match(comm,"^(tar|zip)$"), 0.65,
    true(), 0.55
)
| stats
    count as event_count
    values(comm) as tools_used
    values(decoded) as commands_run
    max(staging_target) as staging_target
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used staging_target commands_run first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["archive_creation_staging"] = {
        "description": "Archive tool execution with PROCTITLE-confirmed staging directory destination",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1074.001", "T1560.001"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with archive creation in staging directory. "
            "Pre-exfiltration data packaging detected."
            if len(check1_results) > 0
            else "No archive creation in staging directories detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Sensitive File Staging
    # staging_write key + PATH record join for destination validation
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"staging_write" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(cp|mv|tee|dd|install|rsync)$")
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
    | where nametype="CREATE" OR nametype="NORMAL"
    | table event_id filepath nametype
]
| where isnotnull(filepath)
| eval sensitive_file=if(
    match(filepath,"(?i)(passwd|shadow|key|pem|pfx|env|config|cred|secret|token|db|sql|backup|dump)"),
    1, 0
)
| eval evidence_weight=case(
    sensitive_file=1 AND match(filepath,"^/dev/shm/"), 0.90,
    sensitive_file=1, 0.85,
    match(filepath,"^/dev/shm/"), 0.75,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_staged
    max(sensitive_file) as sensitive_file
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used sensitive_file files_staged first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["sensitive_file_staging"] = {
        "description": "File copy/move operations writing sensitive files to staging directories",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.85,
        "mitre": ["T1074.001", "T1005"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with sensitive file staging. "
            "Files copied to staging directories before exfiltration."
            if len(check2_results) > 0
            else "No sensitive file staging detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Collection and Staging Score
    # Evidence-separated correlation with event_id deduplication
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("proc_exec" OR "staging_write") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where (key="proc_exec" AND match(comm,"^(tar|zip|gzip|7z|bzip2)$"))
    OR (key="staging_write" AND match(comm,"^(cp|mv|tee|dd|install|rsync)$"))
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
    ("type=PROCTITLE" OR "type=PATH")
    | rex field=_raw "type=(?P<record_type>\\w+)"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
    | eval staging_path=if(
        record_type="PATH"
            AND match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
            AND (nametype="CREATE" OR nametype="NORMAL"),
        filepath, null()
    )
    | eval staging_cmd=if(
        record_type="PROCTITLE"
            AND match(decoded,"(/tmp/|/dev/shm/|/var/tmp/)"),
        decoded, null()
    )
    | where isnotnull(staging_path) OR isnotnull(staging_cmd)
    | stats
        values(staging_path) as staging_path
        values(staging_cmd) as staging_cmd
        by event_id
    | table event_id staging_path staging_cmd
]
| eval technique=case(
    key="proc_exec"
        AND match(comm,"^(tar|zip|gzip|7z|bzip2)$")
        AND isnotnull(staging_cmd),
        "confirmed_archive_staging",
    key="staging_write"
        AND match(comm,"^(cp|mv|tee|dd|install|rsync)$")
        AND isnotnull(staging_path),
        "confirmed_file_staging",
    true(), null()
)
| where isnotnull(technique)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(staging_cmd) as archive_commands
    values(staging_path) as staged_files
    sum(eval(case(
        technique="confirmed_archive_staging", 0.90,
        technique="confirmed_file_staging", 0.85,
        true(), 0.0
    ))) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence auid ses host technique_count techniques_detected archive_commands staged_files first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["combined_collection_staging"] = {
        "description": "Session-scoped correlation of confirmed archive staging and file staging",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1074.001", "T1005", "T1560.001"],
        "architectural_note": "PROCTITLE and PATH evidence kept separate. event_id deduplication applied.",
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with combined collection and staging. "
            "Complete pre-exfiltration data collection sequence detected."
            if len(check3_results) > 0
            else "No combined collection and staging pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Staging Directory Contents
    # Current files in staging dirs for IR triage
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"staging_write" "type=PATH"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
| rex field=_raw "nametype=(?P<nametype>\\w+)"
| where match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
| where nametype="CREATE" OR nametype="NORMAL"
| where auid!=4294967295
| stats
    count as write_count
    values(filepath) as files_written
    min(_time) as first_seen
    max(_time) as last_seen
    by auid host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid host write_count files_written first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["staging_directory_inventory"] = {
        "description": "Files written to staging directories — IR triage inventory",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Staging directory activity: {len(check4_results)} user(s) wrote files to staging locations. "
            "Review files_written for sensitive data indicators."
            if len(check4_results) > 0
            else "No staging directory writes detected."
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
    actions = []

    if checks.get("combined_collection_staging", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Check /tmp, /dev/shm, /var/tmp for staged files — preserve before attacker cleanup")
        actions.append("IMMEDIATE: Block outbound network connections from this host pending investigation")

    if checks.get("archive_creation_staging", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Locate and preserve archive files in staging directories")
        actions.append("SHORT TERM: Inspect archive contents to determine what data was collected")
        actions.append("SHORT TERM: Check network logs for subsequent outbound transfers")

    if checks.get("sensitive_file_staging", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Identify all files staged — determine sensitivity of exposed data")
        actions.append("SHORT TERM: Notify data owners if credential or key files were staged")
        actions.append("REMEDIATION: Rotate any credentials or keys that may have been exposed")

    if not actions:
        actions.append("Continue monitoring — no confirmed collection staging detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("archive_creation_staging", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — data collection and packaging for exfiltration")

    if checks.get("sensitive_file_staging", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — sensitive file staging before exfiltration")

    if checks.get("combined_collection_staging", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — complete collection sequence, exfiltration imminent")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Collection and Staging Behavioral Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
