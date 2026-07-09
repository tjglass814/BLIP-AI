"""
BLIP-AI Playbook — Network Baseline and Zeek Anomaly Investigation
Project 3 — Domain 2: Network Security

Investigates network-level anomalies using Zeek telemetry:
- Long duration external connections (statistical threshold)
- DNS anomalies (volume, NXDOMAIN ratio, TXT ratio)
- C2 beacon patterns (inter-arrival time analysis)
- Cross-domain exfiltration (auditd host signal + Zeek network signal)

Key architectural notes:
- Zeek JSON field extraction requires rex — auto-parse is inconsistent
- local_orig/local_resp may not recognize server IPv6 as local
- auditd success field uses no quotes: success=yes not success="yes"
- Beacon detection uses inter-arrival intervals not raw timestamp stdev

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
        "playbook": "network_baseline",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Long Duration External Connections
    # Statistical threshold: mean + 3σ from 24h baseline
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| where proto="tcp"
| where isnotnull(duration)
| eventstats avg(duration) as baseline_avg stdev(duration) as baseline_std
| eval baseline_std=if(baseline_std<0.1,0.1,baseline_std)
| eval threshold=baseline_avg + (3 * baseline_std)
| where duration > threshold
| eval duration_min=round(duration/60,2)
| eval mb_sent=round(orig_bytes/1024/1024,3)
| eval mb_recv=round(resp_bytes/1024/1024,3)
| eval deviations_above=round((duration-baseline_avg)/baseline_std,1)
| eval evidence_weight=case(
    deviations_above > 10, 0.95,
    deviations_above > 6, 0.85,
    deviations_above > 3, 0.75,
    true(), 0.65
)
| table evidence_weight id.orig_h id.resp_h id.resp_p duration_min deviations_above mb_sent mb_recv conn_state
| sort -deviations_above
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["long_duration_connections"] = {
        "description": "TCP connections statistically anomalous in duration (mean + 3σ)",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "HIGH" if len(check1_results) > 0 else "NONE",
        "mitre": ["T1071.001", "T1573"],
        "known_false_positives": "Tailscale persistent connections on port 443 score HIGH but are expected",
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} connection(s) statistically anomalous in duration. "
            "Review deviations_above column — connections 10+ standard deviations above baseline indicate persistent C2."
            if len(check1_results) > 0
            else "No statistically anomalous duration connections detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — DNS Anomaly Detection
    # Volume, NXDOMAIN ratio, TXT ratio signals
    # NOTE: Requires gateway sensor placement for unicast DNS visibility
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=zeek_dns earliest={earliest} latest={latest}
| where id.resp_p!="5353"
| where NOT match(query,"\\.local$")
| bin _time span=5m
| eval is_nxdomain=if(rcode_name="NXDOMAIN",1,0)
| eval is_txt=if(qtype_name="TXT",1,0)
| stats
    count as total_queries
    sum(is_nxdomain) as nxdomain_count
    sum(is_txt) as txt_count
    dc(query) as unique_queries
    by id.orig_h _time
| eval nxdomain_ratio=round(nxdomain_count/total_queries*100,1)
| eval txt_ratio=round(txt_count/total_queries*100,1)
| eval high_volume=if(total_queries>100,1,0)
| eval high_nxdomain=if(nxdomain_ratio>20 AND total_queries>10,1,0)
| eval high_txt=if(txt_ratio>20 AND total_queries>10,1,0)
| eval signal_count=high_volume+high_nxdomain+high_txt
| where signal_count >= 1
| eval evidence_weight=case(
    signal_count=3, 0.95,
    signal_count=2, 0.85,
    high_nxdomain=1, 0.80,
    high_txt=1, 0.75,
    high_volume=1, 0.65,
    true(), 0.60
)
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table evidence_weight id.orig_h window total_queries unique_queries nxdomain_ratio txt_ratio signal_count
| sort -evidence_weight
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["dns_anomaly"] = {
        "description": "DNS query volume, NXDOMAIN ratio, and TXT query ratio anomalies",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "HIGH" if len(check2_results) > 0 else "NONE",
        "mitre": ["T1071.004", "T1048.003"],
        "deployment_note": "Requires Zeek on gateway/TAP for unicast DNS visibility. Current ens19 deployment only captures mDNS broadcast traffic.",
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} DNS anomaly window(s) detected. "
            "Review nxdomain_ratio for DGA indicators and txt_ratio for tunneling indicators."
            if len(check2_results) > 0
            else "No DNS anomalies detected. Note: unicast DNS not visible in current sensor placement."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — C2 Beacon Pattern Detection
    # Inter-arrival time analysis via streamstats
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main sourcetype=zeek_conn earliest=-6h latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_p\\":(?P<resp_port>\\d+)"
| rex field=_raw "\\"orig_bytes\\":(?P<orig_bytes_val>\\d+)"
| where proto="tcp"
| eval epoch=_time
| sort orig_ip resp_ip resp_port epoch
| streamstats window=1 current=false
    last(epoch) as prev_epoch
    by orig_ip resp_ip resp_port
| eval interval=epoch - prev_epoch
| where isnotnull(interval) AND interval > 0
| stats
    count as conn_count
    avg(interval) as avg_interval
    stdev(interval) as interval_jitter
    avg(orig_bytes_val) as avg_bytes_sent
    by orig_ip resp_ip resp_port
| where conn_count >= 5
| eval interval_jitter=if(isnull(interval_jitter),0,interval_jitter)
| eval beacon_score=case(
    interval_jitter < 5, 1.0,
    interval_jitter < 30, 0.90,
    interval_jitter < 60, 0.80,
    interval_jitter < 120, 0.70,
    true(), 0.0
)
| where beacon_score >= 0.70
| eval avg_interval_min=round(avg_interval/60,2)
| eval interval_jitter=round(interval_jitter,2)
| eval evidence_weight=case(
    beacon_score>=0.90 AND avg_bytes_sent>0, 0.95,
    beacon_score>=0.90, 0.85,
    beacon_score>=0.80, 0.80,
    true(), 0.70
)
| table evidence_weight orig_ip resp_ip resp_port beacon_score conn_count avg_interval_min interval_jitter
| sort -beacon_score
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["beacon_pattern"] = {
        "description": "C2 beacon detection via inter-arrival time interval consistency",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "HIGH" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1071.001", "T1573", "T1090"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} beacon pattern(s) detected. "
            "Review beacon_score and interval_jitter — score 1.0 with jitter <5s indicates highly regular automated callbacks."
            if len(check3_results) > 0
            else "No beacon patterns detected in last 6 hours."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Cross-Domain Exfiltration Score
    # auditd host signal + Zeek network signal correlation
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main (sourcetype=linux_audit OR sourcetype=zeek_conn) earliest={earliest} latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"orig_bytes\\":(?P<orig_bytes_val>\\d+)"
| rex field=_raw "\\"resp_bytes\\":(?P<resp_bytes_val>\\d+)"
| eval endpoint=case(
    sourcetype="linux_audit", "splunk-server",
    sourcetype="zeek_conn" AND match(orig_ip,"^10\\.10\\.10\\."), "splunk-server",
    sourcetype="zeek_conn" AND match(orig_ip,"^192\\.168\\.1\\.234"), "splunk-server",
    true(), null()
)
| eval signal=case(
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"proc_exec\\"")
        AND match(_raw,"comm=\\"curl\\"")
        AND match(_raw,"success=yes"),
    "host_network_tool_exec",
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"proc_exec\\"")
        AND match(_raw,"comm=\\"wget\\"")
        AND match(_raw,"success=yes"),
    "host_network_tool_exec",
    sourcetype="zeek_conn"
        AND match(orig_ip,"^(10\\.10\\.10\\.|192\\.168\\.1\\.234)")
        AND proto="tcp"
        AND match(_raw,"\\"local_resp\\":false"),
    "network_external_connection",
    true(), null()
)
| where isnotnull(signal) AND isnotnull(endpoint)
| eval upload_ratio=if(
    signal="network_external_connection"
        AND orig_bytes_val>0
        AND resp_bytes_val>0,
    round(orig_bytes_val/(resp_bytes_val+1)*100,1), null()
)
| eval large_upload=if(orig_bytes_val>10485760,1,0)
| eval exfil_indicator=if(upload_ratio>200 AND large_upload=1,1,0)
| bin _time span=10m
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    max(upload_ratio) as max_upload_ratio
    max(exfil_indicator) as exfil_indicator
    max(orig_bytes_val) as max_bytes_sent
    min(_time) as first_seen
    max(_time) as last_seen
    by _time endpoint
| where signal_count >= 2
| eval combined_confidence=case(
    exfil_indicator=1, 0.97,
    max_upload_ratio>100 AND max_bytes_sent>1048576, 0.90,
    true(), 0.82
)
| where combined_confidence >= 0.75
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence endpoint signal_count signals_detected max_upload_ratio exfil_indicator max_bytes_sent first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["cross_domain_exfiltration"] = {
        "description": "Cross-domain correlation: auditd curl/wget execution + Zeek external TCP connection",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "CRITICAL" if len(check4_results) > 0 else "NONE",
        "mitre": ["T1041", "T1048", "T1071.001"],
        "interpretation": (
            f"CONFIRMED — {len(check4_results)} cross-domain exfiltration window(s) detected. "
            "Both host tool execution AND network connection confirmed. Review max_bytes_sent and exfil_indicator for severity."
            if len(check4_results) > 0
            else "No cross-domain exfiltration pattern detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 5 — Network Activity Summary for IR Context
    # ------------------------------------------------------------------ #
    check5_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"orig_bytes\\":(?P<orig_bytes_val>\\d+)"
| where match(orig_ip,"^(10\\.10\\.10\\.|192\\.168\\.1\\.234)")
| where proto="tcp"
| stats
    count as connections
    sum(orig_bytes_val) as total_bytes_sent
    dc(resp_ip) as unique_destinations
    max(duration) as max_duration
    avg(duration) as avg_duration
    by orig_ip
| eval total_mb_sent=round(total_bytes_sent/1024/1024,2)
| eval max_duration_min=round(max_duration/60,2)
| eval avg_duration=round(avg_duration,2)
| table orig_ip connections unique_destinations total_mb_sent max_duration_min avg_duration
| sort -connections
"""

    check5_results = connector.search(check5_query)
    evidence["checks"]["network_activity_summary"] = {
        "description": "Network activity summary for IR triage — connections, bytes, destinations",
        "query": check5_query.strip(),
        "result_count": len(check5_results),
        "results": check5_results,
        "severity": "INFO",
        "interpretation": (
            f"Network summary: {len(check5_results)} host(s) with outbound TCP activity. "
            "Review total_mb_sent for exfiltration volume and max_duration_min for persistent connections."
            if len(check5_results) > 0
            else "No outbound TCP activity from lab hosts detected."
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

    if checks.get("cross_domain_exfiltration", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Network tool execution AND external connection confirmed — check for data exfiltration")
        actions.append("IMMEDIATE: Review Zeek conn.log for bytes transferred and destination reputation")
        actions.append("IMMEDIATE: Check auditd for what files were accessed before the network tool ran")

    if checks.get("beacon_pattern", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: Beacon pattern detected — investigate destination IP reputation")
        actions.append("SHORT TERM: Check for corresponding host-side process executing network connections")
        actions.append("SHORT TERM: Review connection history — when did beaconing start?")

    if checks.get("long_duration_connections", {}).get("result_count", 0) > 0:
        actions.append("INVESTIGATE: Long duration connections detected — verify against known-good baselines")
        actions.append("INVESTIGATE: Tailscale connections expected — any non-Tailscale long connections require triage")

    if not actions:
        actions.append("No network anomalies confirmed — continue baseline monitoring")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("cross_domain_exfiltration", {}).get("result_count", 0) > 0:
        phases.append("Actions on Objectives — network tool execution with external connection confirms active exfiltration attempt")

    if checks.get("beacon_pattern", {}).get("result_count", 0) > 0:
        phases.append("Command and Control — regular callback pattern indicates established C2 channel")

    if checks.get("long_duration_connections", {}).get("result_count", 0) > 0:
        phases.append("Command and Control — persistent long-duration connections indicate maintained access")

    if checks.get("dns_anomaly", {}).get("result_count", 0) > 0:
        phases.append("Exfiltration — DNS anomalies indicate possible data exfiltration over DNS channel")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Cross-Domain Exfiltration Score"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
