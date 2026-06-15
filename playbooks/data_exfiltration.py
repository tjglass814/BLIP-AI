"""
BLIP-AI Playbook — Data Exfiltration Detection
Project 11 — Domain 1: Linux and SIEM

Investigates data exfiltration activity:
- Network tool exfiltration (download_tool + PROCTITLE validation)
- Encode and exfiltrate chain (encoding_tool + download_tool correlation)
- Combined cross-project behavioral score (staging + exfiltration signals)

Scoring model: normalized weighted averaging (raw_score/technique_count)
Evidence model: PROCTITLE required for D1, behavioral chain sufficient for D2/D3

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
        "playbook": "data_exfiltration",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Network Tool Exfiltration
    # download_tool key + PROCTITLE validation for argument analysis
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"download_tool" "type=SYSCALL"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
| rex field=_raw "tty=(?P<tty>\\S+)"
| rex field=_raw "success=(?P<success>\\w+)"
| rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
| where success="yes" OR success="1"
| where auid!=4294967295
| where tty!="(none)"
| where match(comm,"^(curl|wget)$")
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
| where has_proctitle=1
| eval raw_ip_dest=if(match(decoded,"https?://\\d+\\.\\d+\\.\\d+\\.\\d+"),1,0)
| eval post_method=if(match(decoded,"-x post|-X POST|--request post|--request POST|--data|--data-binary|-d "),1,0)
| eval evidence_weight=case(
    raw_ip_dest=1 AND post_method=1, 0.95,
    raw_ip_dest=1, 0.85,
    post_method=1, 0.80,
    true(), 0.65
)
| stats
    count as event_count
    values(comm) as tools_used
    values(decoded) as commands_run
    max(raw_ip_dest) as raw_ip_dest
    max(post_method) as post_method
    max(evidence_weight) as evidence_weight
    min(_time) as first_seen
    max(_time) as last_seen
    by auid ses host
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight auid ses host event_count tools_used raw_ip_dest post_method commands_run first_seen last_seen
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["network_tool_exfiltration"] = {
        "description": "curl/wget with PROCTITLE-confirmed raw IP destinations or POST method",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "confidence_weight": 0.95,
        "mitre": ["T1041", "T1048"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} session(s) with network tool exfiltration. "
            "curl/wget making outbound connections with POST or raw IP indicators."
            if len(check1_results) > 0
            else "No network tool exfiltration detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Encode and Exfiltrate Chain
    # base64 + network transfer in same session
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("encoding_tool" OR "download_tool") "type=SYSCALL"
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
    key="encoding_tool" AND comm="base64", "encoding",
    key="download_tool" AND match(comm,"^(curl|wget)$"), "network_transfer",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="encoding", 0.70,
    technique="network_transfer", 0.75,
    true(), 0.60
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
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence auid ses host technique_count techniques_detected tools_used first_seen last_seen
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["encode_exfiltrate_chain"] = {
        "description": "base64 encoding followed by network transfer in same session",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "CRITICAL" if len(check2_results) > 0 else "NONE",
        "confidence_weight": 1.0,
        "mitre": ["T1027", "T1041"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} session(s) with encode-before-exfiltrate pattern. "
            "base64 encoding combined with network transfer indicates content inspection bypass."
            if len(check2_results) > 0
            else "No encode-and-exfiltrate chain detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Combined Exfiltration Behavioral Score
    # Cross-project correlation: staging + encoding + transfer + archive
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
("download_tool" OR "encoding_tool" OR "staging_write" OR "proc_exec") "type=SYSCALL"
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
    key="download_tool" AND match(comm,"^(curl|wget)$"), "network_transfer",
    key="encoding_tool" AND comm="base64", "encoding",
    key="staging_write" AND match(comm,"^(cp|mv|tee|dd|rsync|install)$"), "file_staging",
    key="proc_exec" AND match(comm,"^(tar|zip|gzip)$"), "archive_creation",
    true(), null()
)
| where isnotnull(technique)
| eval technique_weight=case(
    technique="network_transfer", 0.80,
    technique="encoding", 0.70,
    technique="file_staging", 0.75,
    technique="archive_creation", 0.75,
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
    evidence["checks"]["combined_exfiltration_score"] = {
        "description": "Cross-project correlation: staging + encoding + archive + network transfer",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1041", "T1048", "T1027", "T1074.001", "T1560.001"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} session(s) with complete exfiltration behavioral chain. "
            "Multiple technique categories confirm active data exfiltration operation."
            if len(check3_results) > 0
            else "No combined exfiltration pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — IOC Extraction
    # Destination IPs from curl/wget commands
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=linux_audit earliest={earliest} latest={latest}
"type=PROCTITLE"
| rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
| eval proctitle_clean=replace(proctitle_hex,"00"," ")
| eval decoded=lower(urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{{2}})","%" . "\\1")))
| where match(decoded,"^(curl|wget)\\s")
| rex field=decoded "https?://(?P<dest_host>[^/\\s]+)"
| where isnotnull(dest_host)
| stats
    count as connection_count
    values(decoded) as full_commands
    by dest_host
| eval ioc_type="exfiltration_destination"
| sort -connection_count
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["exfiltration_iocs"] = {
        "description": "Destination hosts/IPs from curl/wget commands — actionable network IOCs",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "INFO",
        "interpretation": (
            f"CONFIRMED — {len(check4_results)} unique destination(s) identified. "
            "Block at firewall and report to threat intel."
            if len(check4_results) > 0
            else "No exfiltration destination IOCs extracted."
        )
    }

    # Summary
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

    if checks.get("combined_exfiltration_score", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Block all outbound connections from this host")
        actions.append("IMMEDIATE: Preserve network logs for forensic analysis")

    if checks.get("exfiltration_iocs", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Block destination IPs/hosts at OPNsense firewall")
        actions.append("SHORT TERM: Submit destination IPs to threat intel platform")

    if checks.get("network_tool_exfiltration", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Review all curl/wget commands run in affected session")
        actions.append("SHORT TERM: Determine what data was transferred and to where")

    if checks.get("encode_exfiltrate_chain", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Recover base64-encoded content from session history if available")
        actions.append("REMEDIATION: Rotate credentials and keys that may have been exfiltrated")

    if not actions:
        actions.append("Continue monitoring — no confirmed exfiltration detected")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("network_tool_exfiltration", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — active data exfiltration via network tools")

    if checks.get("encode_exfiltrate_chain", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — encoded exfiltration, content inspection bypass attempted")

    if checks.get("combined_exfiltration_score", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — complete exfiltration chain confirmed")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Exfiltration Behavioral Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
