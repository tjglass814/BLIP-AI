"""
BLIP-AI Playbook — Network Data Exfiltration Investigation
Project 5 — Domain 2: Network Security

Investigates data exfiltration across network and host telemetry:
- Large outbound transfer anomaly (statistical per-host threshold)
- Large cumulative outbound transfer (absolute threshold per hour)
- Cross-domain staging and exfiltration (auditd + Zeek correlation)
- Slow drip exfiltration (sustained low-volume transfers)
- Combined exfiltration score (multi-signal weighted confidence)

Key architectural notes:
- Use orig_ip_bytes not orig_bytes — cluster mode drops application-layer bytes
- Splunk bin() is wall-clock aligned — use 2h windows for cross-domain correlation
- Splunk postgres fires staging_write key — always exclude /opt/splunk
- CDN IP rotation defeats slow drip per-destination grouping in lab

Author: Taylor Glass
"""

import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from splunk_connector import SplunkConnector


def run(alert_name: str, earliest: str = "-24h", latest: str = "now") -> dict:
    connector = SplunkConnector()
    evidence = {
        "playbook": "network_exfiltration",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Large Outbound Transfer Anomaly
    # Per-host statistical threshold: mean + 3σ
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| rex field=_raw "\\"orig_bytes\\":(?P<orig_bytes_val>\\d+)"
| rex field=_raw "\\"resp_bytes\\":(?P<resp_bytes_val>\\d+)"
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_p\\":(?P<resp_port>\\d+)"
| eval orig_bytes=tonumber(orig_bytes_val)
| eval resp_bytes=tonumber(resp_bytes_val)
| where isnotnull(orig_bytes) AND orig_bytes > 0
| where proto="tcp"
| eventstats avg(orig_bytes) as baseline_avg stdev(orig_bytes) as baseline_std by orig_ip
| eval baseline_std=if(baseline_std<1,1,baseline_std)
| eval threshold=baseline_avg + (3 * baseline_std)
| where orig_bytes > threshold
| eval orig_mb=round(orig_bytes/1024/1024,2)
| eval resp_mb=round(resp_bytes/1024/1024,2)
| eval upload_ratio=round(orig_bytes/(resp_bytes+1),2)
| eval deviations_above=min(round((orig_bytes-baseline_avg)/baseline_std,1),100)
| eval destination_type=case(
    match(resp_ip,"^10\\.10\\.10\\."),"internal",
    match(resp_ip,"^192\\.168\\."),"home_network",
    true(),"external"
)
| eval evidence_weight=case(
    orig_mb > 50 AND upload_ratio > 2 AND destination_type="external", 0.97,
    orig_mb > 10 AND upload_ratio > 2 AND destination_type="external", 0.90,
    orig_mb > 50 AND destination_type="external", 0.85,
    orig_mb > 10 AND destination_type="external", 0.80,
    true(), 0.65
)
| where evidence_weight >= 0.75
| table evidence_weight orig_ip resp_ip resp_port orig_mb resp_mb upload_ratio deviations_above destination_type
| sort -orig_mb
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["large_transfer_anomaly"] = {
        "description": "Per-host statistical anomaly detection — transfers >3σ above baseline",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "HIGH" if len(check1_results) > 0 else "NONE",
        "mitre": ["T1041", "T1048"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} statistically anomalous transfer(s) detected. "
            "Review deviations_above and destination_type — external transfers with high upload ratio indicate active exfiltration."
            if len(check1_results) > 0
            else "No statistically anomalous transfers detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Large Cumulative Outbound Transfer
    # Absolute threshold: >10MB per hour to external destination
    # Uses orig_ip_bytes — reliable in Zeek cluster mode
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| rex field=_raw "\\"orig_ip_bytes\\":(?P<orig_ip_bytes_val>\\d+)"
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_p\\":(?P<resp_port>\\d+)"
| eval orig_bytes=tonumber(orig_ip_bytes_val)
| where isnotnull(orig_bytes)
| where proto="tcp"
| where NOT match(resp_ip,"^192\\.168\\.")
| where NOT match(resp_ip,"^10\\.10\\.10\\.")
| where NOT match(resp_ip,"^224\\.")
| bin _time span=1h
| stats
    sum(orig_bytes) as total_bytes_sent
    count as connections
    by orig_ip resp_ip _time
| eval total_mb=round(total_bytes_sent/1024/1024,2)
| where total_mb > 10
| eval evidence_weight=case(
    total_mb > 100, 0.97,
    total_mb > 50, 0.90,
    total_mb > 20, 0.85,
    total_mb > 10, 0.75,
    true(), 0.65
)
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table evidence_weight orig_ip resp_ip total_mb connections window
| sort -total_mb
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["cumulative_transfer"] = {
        "description": "Cumulative outbound transfer >10MB per hour to external destinations",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "HIGH" if len(check2_results) > 0 else "NONE",
        "mitre": ["T1048"],
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} large cumulative transfer(s) detected. "
            "Review total_mb and dest IP — significant outbound volume to external destination."
            if len(check2_results) > 0
            else "No large cumulative transfers detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — Cross-Domain Staging and Exfiltration
    # auditd staging_write + Zeek large outbound in same 2-hour window
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main (sourcetype=linux_audit OR sourcetype=zeek_conn) earliest={earliest} latest={latest}
| rex field=_raw "\\"orig_ip_bytes\\":(?P<orig_ip_bytes_val>\\d+)"
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "auid=(?P<auid>\\d+)"
| eval signal=case(
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"staging_write\\"")
        AND match(_raw,"success=yes")
        AND match(_raw,"comm=\\"tar\\"|comm=\\"zip\\"|comm=\\"cp\\"|comm=\\"dd\\"|comm=\\"gzip\\"")
        AND auid!="4294967295"
        AND NOT match(_raw,"exe=\\"/opt/splunk"),
    "host_data_staged",
    sourcetype="zeek_conn"
        AND match(orig_ip,"^192\\.168\\.1\\.234")
        AND proto="tcp"
        AND NOT match(resp_ip,"^192\\.168\\.")
        AND NOT match(resp_ip,"^10\\.10\\.10\\.")
        AND tonumber(orig_ip_bytes_val) > 1048576,
    "network_large_outbound",
    true(), null()
)
| where isnotnull(signal)
| eval user_auid=if(signal="host_data_staged", auid, null())
| eval endpoint="splunk-server"
| bin _time span=2h
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    max(tonumber(orig_ip_bytes_val)) as max_bytes
    values(resp_ip) as dest_ips
    dc(user_auid) as user_count
    values(user_auid) as auids
    min(_time) as first_seen
    max(_time) as last_seen
    by _time endpoint
| where signal_count >= 2
| where user_count <= 1
| eval max_mb=round(max_bytes/1024/1024,2)
| eval combined_confidence=case(
    max_mb > 50, 0.97,
    max_mb > 10, 0.90,
    true(), 0.82
)
| where combined_confidence >= 0.80
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence endpoint signal_count signals_detected auids max_mb dest_ips first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["cross_domain_staging"] = {
        "description": "Cross-domain correlation: auditd staging + Zeek large outbound in same 2-hour window",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1074.001", "T1041"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} cross-domain exfiltration chain(s) detected. "
            "File staging AND network transfer confirmed in same window by same user."
            if len(check3_results) > 0
            else "No cross-domain staging and exfiltration pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Slow Drip Exfiltration
    # Sustained low-volume transfers to same destination over 24 hours
    # Note: CDN targets defeat this in lab — works against stable C2 IPs
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| rex field=_raw "\\"orig_ip_bytes\\":(?P<orig_ip_bytes_val>\\d+)"
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_p\\":(?P<resp_port>\\d+)"
| eval orig_bytes=tonumber(orig_ip_bytes_val)
| where isnotnull(orig_bytes) AND orig_bytes > 0
| where proto="tcp"
| where NOT match(resp_ip,"^192\\.168\\.")
| where NOT match(resp_ip,"^10\\.10\\.10\\.")
| where NOT match(resp_ip,"^224\\.")
| stats
    count as connection_count
    sum(orig_bytes) as total_bytes
    avg(orig_bytes) as avg_bytes_per_conn
    min(_time) as first_seen
    max(_time) as last_seen
    by orig_ip resp_ip resp_port
| eval total_mb=round(total_bytes/1024/1024,2)
| eval avg_kb=round(avg_bytes_per_conn/1024,1)
| eval duration_hours=round((last_seen-first_seen)/3600,2)
| where connection_count >= 3
| where total_mb > 1
| where avg_kb < 2048
| eval evidence_weight=case(
    total_mb > 50 AND connection_count > 20, 0.95,
    total_mb > 20 AND connection_count > 10, 0.90,
    total_mb > 10 AND connection_count > 5, 0.85,
    total_mb > 5 AND connection_count > 5, 0.75,
    total_mb > 1 AND connection_count >= 3, 0.70,
    true(), 0.65
)
| where evidence_weight >= 0.70
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table evidence_weight orig_ip resp_ip resp_port total_mb avg_kb connection_count duration_hours first_seen last_seen
| sort -total_mb
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["slow_drip"] = {
        "description": "Slow drip exfiltration — 3+ connections to same destination with cumulative >1MB and avg <2MB",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "MEDIUM" if len(check4_results) > 0 else "NONE",
        "mitre": ["T1048", "T1041"],
        "known_limitation": "CDN IP rotation defeats per-destination grouping in lab — effective against stable C2 infrastructure",
        "interpretation": (
            f"CONFIRMED — {len(check4_results)} slow drip pattern(s) detected. "
            "Sustained low-volume transfers to same destination indicate deliberate threshold evasion."
            if len(check4_results) > 0
            else "No slow drip patterns detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 5 — Combined Exfiltration Score
    # Multi-signal weighted confidence
    # ------------------------------------------------------------------ #
    check5_query = f"""
search index=main (sourcetype=zeek_conn OR sourcetype=linux_audit) earliest={earliest} latest={latest}
| rex field=_raw "\\"orig_ip_bytes\\":(?P<orig_ip_bytes_val>\\d+)"
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "auid=(?P<auid>\\d+)"
| eventstats avg(tonumber(orig_ip_bytes_val)) as baseline_avg stdev(tonumber(orig_ip_bytes_val)) as baseline_std by orig_ip
| eval baseline_std=if(baseline_std<1,1,baseline_std)
| eval orig_bytes=tonumber(orig_ip_bytes_val)
| eval signal=case(
    sourcetype="zeek_conn"
        AND proto="tcp"
        AND NOT match(resp_ip,"^192\\.168\\.")
        AND NOT match(resp_ip,"^10\\.10\\.10\\.")
        AND isnotnull(orig_bytes)
        AND orig_bytes > (baseline_avg + 3*baseline_std)
        AND orig_bytes > 10485760,
    "large_transfer_anomaly",
    sourcetype="zeek_conn"
        AND proto="tcp"
        AND NOT match(resp_ip,"^192\\.168\\.")
        AND NOT match(resp_ip,"^10\\.10\\.10\\.")
        AND isnotnull(orig_bytes)
        AND orig_bytes > 1048576,
    "large_outbound",
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"staging_write\\"")
        AND match(_raw,"success=yes")
        AND match(_raw,"comm=\\"tar\\"|comm=\\"zip\\"|comm=\\"cp\\"|comm=\\"dd\\"|comm=\\"gzip\\"")
        AND auid!="4294967295"
        AND NOT match(_raw,"exe=\\"/opt/splunk"),
    "host_data_staged",
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"proc_exec\\"")
        AND match(_raw,"comm=\\"curl\\"|comm=\\"wget\\"")
        AND match(_raw,"success=yes"),
    "network_tool_exec",
    true(), null()
)
| where isnotnull(signal)
| eval signal_weight=case(
    signal="large_transfer_anomaly", 0.90,
    signal="host_data_staged", 0.85,
    signal="large_outbound", 0.75,
    signal="network_tool_exec", 0.70,
    true(), 0.50
)
| eval endpoint="splunk-server"
| bin _time span=2h
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    sum(signal_weight) as raw_score
    max(orig_bytes) as max_bytes
    values(resp_ip) as dest_ips
    min(_time) as first_seen
    max(_time) as last_seen
    by _time endpoint
| where signal_count >= 2
| eval max_mb=round(max_bytes/1024/1024,2)
| eval combined_confidence=min(round(raw_score/signal_count * 1.15, 2), 1.0)
| where combined_confidence >= 0.75
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence endpoint signal_count signals_detected max_mb dest_ips first_seen last_seen
| sort -combined_confidence
"""

    check5_results = connector.search(check5_query)
    evidence["checks"]["combined_score"] = {
        "description": "Combined exfiltration score — weighted multi-signal confidence across 2-hour window",
        "query": check5_query.strip(),
        "result_count": len(check5_results),
        "results": check5_results,
        "severity": "CRITICAL" if len(check5_results) > 0 else "NONE",
        "mitre": ["T1041", "T1048", "T1074.001", "T1059"],
        "interpretation": (
            f"CONFIRMED — {len(check5_results)} multi-signal exfiltration pattern(s) detected. "
            "Combined confidence from independent signals — immediate investigation required."
            if len(check5_results) > 0
            else "No multi-signal exfiltration patterns detected."
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
            "CRITICAL" if any(
                v.get("severity") == "CRITICAL" and v.get("result_count", 0) > 0
                for v in evidence["checks"].values()
            )
            else "HIGH" if len(confirmed_checks) >= 1
            else "LOW"
        ),
        "recommended_actions": _get_recommendations(evidence["checks"]),
        "kill_chain_phase": _get_kill_chain(evidence["checks"])
    }

    return evidence


def _get_recommendations(checks: dict) -> list:
    actions = []

    if checks.get("combined_score", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Multiple exfiltration signals confirmed — block outbound to destination IPs at OPNsense")
        actions.append("IMMEDIATE: Check auditd for what files were staged and what commands ran before the transfer")
        actions.append("IMMEDIATE: Review Zeek conn.log for total bytes transferred and all destination IPs")
        actions.append("IMMEDIATE: Preserve /tmp contents — staged files may still be present")

    if checks.get("cross_domain_staging", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Staging confirmed — identify what data was archived and whether it was sensitive")
        actions.append("SHORT TERM: Check /tmp and /dev/shm for staged archives")

    if checks.get("large_transfer_anomaly", {}).get("result_count", 0) > 0:
        actions.append("INVESTIGATE: Large transfer detected — verify against known-good backup or update activity")
        actions.append("INVESTIGATE: Check destination IP reputation")

    if checks.get("slow_drip", {}).get("result_count", 0) > 0:
        actions.append("INVESTIGATE: Slow drip pattern — check destination IP and whether connections are expected")

    if not actions:
        actions.append("No exfiltration confirmed — continue monitoring")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("cross_domain_staging", {}).get("result_count", 0) > 0:
        phases.append("Collection — data staged locally before exfiltration")

    if any(
        checks.get(k, {}).get("result_count", 0) > 0
        for k in ["large_transfer_anomaly", "cumulative_transfer", "slow_drip"]
    ):
        phases.append("Exfiltration — data transferred to external destination")

    if checks.get("combined_score", {}).get("result_count", 0) > 0:
        phases.append("Complete Chain — collection and exfiltration confirmed across host and network telemetry")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Exfiltration Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
