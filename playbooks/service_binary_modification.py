"""
BLIP-AI Playbook — Service and Binary Modification Detection
Project 12 — Domain 1: Linux and SIEM

Investigates system integrity attacks:
- System binary modification (binary_modification key + PATH validation)
- Shared library and environment hijacking (library_modification + env_modification + PROCTITLE)
- Combined session-scoped behavioral correlation

Architectural notes:
- comm-based classification only — no hardcoded syscall numbers
- mvjoin() for multivalue filepath pattern matching
- nametype!="PARENT" for comprehensive file event coverage
- PROCTITLE required for LD_PRELOAD confirmation

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
        "playbook": "service_binary_modification",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — System Binary Modification
    # binary_modification key + PATH record validation
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"binary_modification" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"^(/usr/bin/|/usr/sbin/|/bin/|/sbin/)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval action_type=case(
    match(comm,"^(cp|install)$"), "binary_replaced",
    match(comm,"^(mv)$"), "binary_renamed",
    match(comm,"^(rm)$"), "binary_deleted",
    match(comm,"^(dd|tee)$"), "binary_written",
    match(comm,"^(touch)$"), "binary_touched",
    true(), "binary_modified"
)
| eval evidence_weight=case(
    match(comm,"^(cp|mv|install)$"), 0.90,
    match(comm,"^(dd|tee)$"), 0.85,
    match(comm,"^(rm)$"), 0.75,
    match(comm,"^(touch)$"), 0.65,
    true(), 0.70
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as binaries_affected
    values(action_type) as actions
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used actions binaries_affected first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["system_binary_modification"] = {
        "description": "Writes, replacements, and deletions of system binary directory files from interactive sessions",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1574.006", "T1543"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with system binary modification. "
            "Interactive session writing to binary directories — potential trojanized binary."
            if len(check1_results) > 0
            else "No system binary modification detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Shared Library and Environment Hijacking
    # library_modification + env_modification + PROCTITLE LD_PRELOAD validation
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("library_modification" OR "env_modification") "type=SYSCALL"
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
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
    ("type=PATH" OR "type=PROCTITLE")
    | rex field=_raw "type=(?P<record_type>\\w+)"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
    | eval proctitle_clean=replace(proctitle_hex,"00"," ")
    | eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
    | eval path_match=if(
        record_type="PATH"
            AND match(filepath,"^(/lib/|/lib64/|/usr/lib/|/usr/lib64/|/etc/ld\\.so\\.conf$|/etc/ld\\.so\\.conf\\.d/|/etc/environment$)")
            AND nametype!="PARENT",
        filepath, null()
    )
    | eval preload_confirmed=if(
        record_type="PROCTITLE"
            AND match(decoded,"(?i)(ld_preload=|ld_library_path=)"),
        1, 0
    )
    | where isnotnull(path_match) OR preload_confirmed=1
    | stats
        values(path_match) as filepath
        max(preload_confirmed) as preload_confirmed
        by event_id
    | table event_id filepath preload_confirmed
]
| where isnotnull(filepath)
| eval hijack_type=case(
    key="env_modification" AND preload_confirmed=1, "ld_preload_env_injection",
    key="env_modification", "environment_modification",
    key="library_modification" AND match(filepath,"\\.so(\\.[0-9]+)*$"), "shared_library_planted",
    key="library_modification" AND match(filepath,"ld\\.so\\.conf(\\.d/.*)?$"), "library_path_manipulation",
    true(), "library_modification"
)
| eval evidence_weight=case(
    hijack_type="ld_preload_env_injection", 0.95,
    hijack_type="shared_library_planted", 0.90,
    hijack_type="library_path_manipulation", 0.85,
    hijack_type="environment_modification", 0.80,
    true(), 0.70
)
| stats
    count as event_count
    values(comm) as tools_used
    values(filepath) as files_affected
    values(hijack_type) as hijack_types
    max(preload_confirmed) as preload_confirmed
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used hijack_types preload_confirmed files_affected first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["library_env_hijacking"] = {
        "description": "Shared library planting, library path manipulation, and LD_PRELOAD injection",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 0.90,
        "mitre": ["T1574.006", "T1574.007"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with library or environment hijacking. "
            "Malicious code injection into system library path or environment detected."
            if len(check2_results) > 0
            else "No library or environment hijacking detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined System Integrity Score
    # Session-scoped correlation of all four technique categories
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("binary_modification" OR "library_modification" OR "env_modification") "type=SYSCALL"
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
| join type=left event_id [
    search index=main sourcetype=linux_audit earliest={earliest} latest={latest} "type=PATH"
    | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
    | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
    | rex field=_raw "nametype=(?P<nametype>\\w+)"
    | where match(filepath,"^(/usr/bin/|/usr/sbin/|/bin/|/sbin/|/lib/|/lib64/|/usr/lib/|/usr/lib64/|/etc/ld\\.so\\.conf$|/etc/ld\\.so\\.conf\\.d/|/etc/environment$)")
    | where nametype!="PARENT"
    | stats values(filepath) as filepath by event_id
    | table event_id filepath
]
| where isnotnull(filepath)
| eval technique=case(
    key="binary_modification", "binary_modification",
    key="library_modification" AND match(mvjoin(filepath," "),"\\.so(\\.[0-9]+)*$"), "library_planted",
    key="library_modification" AND match(mvjoin(filepath," "),"ld\\.so\\.conf(\\.d/.*)?$"), "library_path_manipulation",
    key="env_modification" AND match(mvjoin(filepath," "),"^/etc/environment$"), "environment_modification",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="binary_modification", 0.90,
    technique="library_planted", 0.90,
    technique="library_path_manipulation", 0.85,
    technique="environment_modification", 0.80,
    true(), 0.60
)
| stats
    dc(technique) as technique_count
    values(technique) as techniques_detected
    values(comm) as tools_used
    values(filepath) as files_affected
    sum(technique_weight) as raw_score
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| where technique_count >= 2
| eval combined_confidence=min(round(raw_score/technique_count * 1.10, 2), 1.0)
| where combined_confidence >= 0.75
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence auid ses host technique_count techniques_detected tools_used files_affected first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["combined_system_integrity"] = {
        "description": "Session-scoped correlation of binary, library, and environment modification techniques",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1574.006", "T1574.007", "T1543", "T1601"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with combined system integrity attack. "
            "Multiple modification categories in same session — high-confidence coordinated tampering."
            if len(check3_results) > 0
            else "No combined system integrity attack pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Affected File Inventory
    # All files modified in watched directories for IR triage
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("binary_modification" OR "library_modification" OR "env_modification") "type=PATH"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
| rex field=_raw "nametype=(?P<nametype>\\w+)"
| rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
| where match(filepath,"^(/usr/bin/|/usr/sbin/|/bin/|/sbin/|/lib/|/lib64/|/usr/lib/|/usr/lib64/|/etc/ld\\.so\\.conf|/etc/environment)")
| where nametype!="PARENT"
| where auid!=4294967295
| stats
    count as modification_count
    values(filepath) as files_modified
    values(key) as keys_fired
    min(_time) as first_seen
    max(_time) as last_seen
    by auid host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table auid host modification_count files_modified keys_fired first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["affected_file_inventory"] = {
        "description": "All files modified in watched system directories — IR triage inventory",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"Inventory: {len(check4_results)} user(s) modified files in system directories. "
            "Review files_modified for unauthorized changes requiring hash verification."
            if len(check4_results) > 0
            else "No system directory modifications detected."
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

    if checks.get("combined_system_integrity", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Isolate host — coordinated system integrity attack confirmed")
        actions.append("IMMEDIATE: Do not trust any output from modified binaries (ps, ls, netstat)")

    if checks.get("system_binary_modification", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Hash all binaries in /usr/bin, /usr/sbin against known-good baseline")
        actions.append("SHORT TERM: Replace affected binaries from trusted source or package manager")
        actions.append("REMEDIATION: Run apt --reinstall install <package> for affected binaries")

    if checks.get("library_env_hijacking", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Check /etc/environment for LD_PRELOAD entries — remove if present")
        actions.append("IMMEDIATE: Check /etc/ld.so.conf.d/ for unauthorized .conf files")
        actions.append("SHORT TERM: Run ldconfig -p to check current library cache")
        actions.append("REMEDIATION: Remove malicious .so files and run ldconfig to rebuild cache")

    if not actions:
        actions.append("Continue monitoring — no confirmed system integrity attacks detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("system_binary_modification", {}).get("result_count", 0) > 0:
        phases.append("Installation — system binary replaced for rootkit or persistence")

    if checks.get("library_env_hijacking", {}).get("result_count", 0) > 0:
        phases.append("Installation — shared library or LD_PRELOAD manipulation for code injection")

    if checks.get("combined_system_integrity", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — coordinated system tampering, host integrity compromised")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Service and Binary Modification Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
