"""
BLIP-AI Playbook — Resource and Stability Anomaly Detection
Project 13 — Domain 1: Linux and SIEM

Investigates resource consumption anomalies:
- Process creation storms (process_creation key — clone/fork syscalls)
- Disk write storms to staging directories (staging_write key)
- Combined cross-project resource anomaly correlation

Design notes:
- Severity tied directly to peak_per_minute not indirectly through evidence_weight
- postgres filtered from staging_write — Splunk internal process noise
- tty!=(none) eliminates splunkd daemon thread creation noise
- Resource anomaly = moderate confidence signal; combined score = high confidence

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
        "playbook": "resource_anomaly",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Process Creation Storm
    # process_creation key — clone/fork syscall monitoring
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"process_creation" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "ppid=(?P<ppid>\\d+)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| bin _time span=1m
| stats
    count as process_count
    dc(comm) as unique_processes
    values(comm) as process_names
    values(ppid) as parent_pids
    by auid ses host _time
| where process_count >= 20
| eval evidence_weight=case(
    process_count>=100, 0.90,
    process_count>=50, 0.80,
    process_count>=20, 0.70,
    true(), 0.60
)
| stats
    sum(process_count) as total_processes
    max(process_count) as peak_per_minute
    max(unique_processes) as peak_unique_processes
    max(evidence_weight) as evidence_weight
    values(process_names) as process_names
    values(parent_pids) as parent_pids
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host total_processes peak_per_minute peak_unique_processes process_names parent_pids first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["process_creation_storm"] = {
        "description": "Unusually high process creation volume from interactive sessions",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1059"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with process creation storm. "
            "High process creation volume — investigate parent PIDs to distinguish attack from build activity."
            if len(check1_results) > 0
            else "No process creation storm detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Disk Write Storm to Staging Directory
    # staging_write key — volume analysis with PATH validation
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"staging_write" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="postgres"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"^(/tmp/|/dev/shm/|/var/tmp/)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| bin _time span=1m
| stats
    count as write_count
    dc(filepath) as unique_files
    values(comm) as tools_used
    values(filepath) as files_written
    by auid ses host _time
| where write_count >= 5
| eval evidence_weight=case(
    write_count>=20, 0.90,
    write_count>=10, 0.80,
    write_count>=5, 0.70,
    true(), 0.60
)
| stats
    sum(write_count) as total_writes
    max(write_count) as peak_per_minute
    max(unique_files) as peak_unique_files
    max(evidence_weight) as evidence_weight
    values(tools_used) as tools_used
    values(files_written) as files_written
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host total_writes peak_per_minute peak_unique_files tools_used files_written first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["disk_write_storm"] = {
        "description": "Anomalous write volume to staging directories from interactive sessions",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1074.001"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with disk write storm. "
            "High volume writes to staging directories — review files_written for sensitive data indicators."
            if len(check2_results) > 0
            else "No disk write storm detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Resource and Stability Anomaly Score
    # Cross-project correlation: process + disk + archive + network + encoding
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("process_creation" OR "staging_write" OR "proc_exec" OR "download_tool" OR "encoding_tool") "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where comm!="postgres"
| eval technique=case(
    key="process_creation" AND match(comm,"^(bash|sh|python|perl|php|nc)$"), "process_storm",
    key="staging_write" AND match(comm,"^(dd|cp|mv|tee|rsync)$"), "disk_storm",
    key="proc_exec" AND match(comm,"^(tar|gzip|zip)$"), "archive_activity",
    key="download_tool" AND match(comm,"^(curl|wget)$"), "network_transfer",
    key="encoding_tool" AND comm="base64", "encoding",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="process_storm", 0.75,
    technique="disk_storm", 0.80,
    technique="archive_activity", 0.75,
    technique="network_transfer", 0.80,
    technique="encoding", 0.70,
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
    evidence["checks"]["combined_resource_anomaly"] = {
        "description": "Cross-project correlation of process, disk, archive, network, and encoding anomalies",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1059", "T1074.001", "T1560.001", "T1041", "T1027"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with combined resource anomaly pattern. "
            "Multiple malicious workload indicators in same session — high confidence active attack."
            if len(check3_results) > 0
            else "No combined resource anomaly pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Recent High-Volume Process Sessions
    # Top sessions by process creation volume for IR triage
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"process_creation" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| where auid!=4294967295
| where tty!="(none)"
| stats
    count as total_forks
    dc(comm) as unique_processes
    values(comm) as process_names
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| sort -total_forks
| head 10
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid ses host total_forks unique_processes process_names first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["top_fork_sessions"] = {
        "description": "Top 10 sessions by process creation volume — IR triage",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Top {len(check4_results)} session(s) by fork volume. "
            "Review process_names and correlate with network activity for triage."
            if len(check4_results) > 0
            else "No process creation data in window."
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

    if checks.get("combined_resource_anomaly", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Investigate session — multiple malicious workload indicators confirmed")
        actions.append("IMMEDIATE: Check running processes for cryptominers or password crackers")

    if checks.get("process_creation_storm", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Review parent PIDs to distinguish attack from legitimate build activity")
        actions.append("SHORT TERM: Check for cryptominer or parallelized attack tool processes")

    if checks.get("disk_write_storm", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Check /tmp, /dev/shm, /var/tmp for staged files before cleanup")
        actions.append("SHORT TERM: Determine what data was written and whether it was subsequently transferred")

    if not actions:
        actions.append("Continue monitoring — no confirmed resource anomalies detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("process_creation_storm", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — high process creation volume, possible cryptominer or fork bomb")

    if checks.get("disk_write_storm", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — high disk write volume to staging directories")

    if checks.get("combined_resource_anomaly", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — combined resource consumption pattern confirms active malicious workload")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Resource and Stability Anomaly Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
