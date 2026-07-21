"""
BLIP-AI Playbook — Network Reconnaissance and Lateral Movement Investigation
Project 4 — Domain 2: Network Security

Investigates network-based attack chain:
- Port scanning from lab hosts (Zeek conn.log)
- Internal host discovery (Zeek conn.log)
- SSH lateral movement (Zeek + auditd correlation)
- Combined kill-chain score (multi-signal attribution)

Key architectural notes:
- id.resp_p field unreliable — always use rex for port extraction
- ARP-based discovery invisible to Zeek (Layer 2 blind spot)
- Zeek cluster mode has 1-2 minute log aggregation delay
- auditd USER_START hostname= field = SSH client IP (correlation key)
- dc(audit_session) <= 1 required to validate session belongs to SSH login

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
        "playbook": "lateral_movement",
        "alert_name": alert_name,
        "investigation_time": datetime.utcnow().isoformat(),
        "earliest": earliest,
        "latest": latest,
        "checks": {}
    }

    # ------------------------------------------------------------------ #
    # CHECK 1 — Port Scan Detection
    # Zeek conn.log: unique ports + failure ratio in 1-minute windows
    # ------------------------------------------------------------------ #
    check1_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| where match(orig_ip,"^10\\.10\\.10\\.")
| bin _time span=1m
| stats
    dc(id.resp_p) as unique_ports
    count as total_conns
    sum(eval(if(conn_state="S0",1,0))) as s0_count
    sum(eval(if(conn_state="REJ",1,0))) as rej_count
    by orig_ip _time
| eval failed_ratio=round((s0_count+rej_count)/total_conns*100,1)
| eval evidence_weight=case(
    unique_ports > 500, 0.95,
    unique_ports > 100, 0.90,
    unique_ports > 50,  0.85,
    unique_ports > 20,  0.75,
    true(), 0.65
)
| where unique_ports > 20
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table evidence_weight orig_ip window unique_ports total_conns s0_count rej_count failed_ratio
| sort -unique_ports
"""

    check1_results = connector.search(check1_query)
    evidence["checks"]["port_scan"] = {
        "description": "Port scanning behavior — unique destination ports per source in 1-minute windows",
        "query": check1_query.strip(),
        "result_count": len(check1_results),
        "results": check1_results,
        "severity": "CRITICAL" if len(check1_results) > 0 else "NONE",
        "mitre": ["T1046"],
        "interpretation": (
            f"CONFIRMED — {len(check1_results)} scan window(s) detected. "
            "Review unique_ports and failed_ratio — 99%+ failure rate with 500+ ports indicates aggressive nmap-style scan."
            if len(check1_results) > 0
            else "No port scanning detected from lab hosts."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 2 — Internal Host Discovery
    # Zeek conn.log: unique internal IPs contacted in 2-minute windows
    # NOTE: ARP-based discovery invisible — Layer 2 blind spot
    # ------------------------------------------------------------------ #
    check2_query = f"""
search index=main sourcetype=zeek_conn earliest={earliest} latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| where match(orig_ip,"^10\\.10\\.10\\.")
| where match(resp_ip,"^10\\.10\\.10\\.")
| where NOT match(resp_ip,"^224\\.")
| where NOT match(resp_ip,"^239\\.")
| where id.resp_p!="5353"
| where proto!="icmp6"
| bin _time span=2m
| stats
    dc(resp_ip) as unique_hosts
    count as total_conns
    values(resp_ip) as hosts_contacted
    by orig_ip _time
| where unique_hosts >= 3
| eval evidence_weight=case(
    unique_hosts > 10, 0.95,
    unique_hosts > 5,  0.85,
    unique_hosts >= 3, 0.75,
    true(), 0.65
)
| eval window=strftime(_time,"%Y-%m-%d %H:%M")
| table evidence_weight orig_ip window unique_hosts total_conns hosts_contacted
| sort -unique_hosts
"""

    check2_results = connector.search(check2_query)
    evidence["checks"]["host_discovery"] = {
        "description": "Internal host discovery — unique internal IPs contacted in 2-minute windows",
        "query": check2_query.strip(),
        "result_count": len(check2_results),
        "results": check2_results,
        "severity": "HIGH" if len(check2_results) > 0 else "NONE",
        "mitre": ["T1018"],
        "known_limitation": "ARP-based subnet sweeps (nmap -sn on local segment) not visible — ARP is Layer 2, not captured in Zeek conn.log",
        "interpretation": (
            f"CONFIRMED — {len(check2_results)} discovery window(s) detected. "
            "Review hosts_contacted to identify which internal systems were probed."
            if len(check2_results) > 0
            else "No internal host discovery detected. Note: ARP-based sweeps not detectable."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 3 — SSH Lateral Movement
    # Zeek SSH inbound + auditd session creation + command execution
    # Correlated by audit session ID
    # ------------------------------------------------------------------ #
    check3_query = f"""
search index=main (sourcetype=zeek_conn OR sourcetype=linux_audit) earliest={earliest} latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_p\\":(?P<resp_port>\\d+)"
| rex field=_raw "addr=(?P<ssh_src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| eval signal=case(
    sourcetype="zeek_conn"
        AND match(orig_ip,"^10\\.10\\.10\\.")
        AND resp_ip="10.10.10.198"
        AND resp_port="22"
        AND proto="tcp"
        AND (conn_state="SF" OR conn_state="S1" OR conn_state="OTH"),
    "network_ssh_inbound",
    sourcetype="linux_audit"
        AND match(_raw,"type=USER_START")
        AND match(_raw,"exe=\\"/usr/sbin/sshd\\"")
        AND match(_raw,"res=success")
        AND match(ssh_src_ip,"^10\\.10\\.10\\."),
    "host_ssh_session_created",
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"proc_exec\\"")
        AND match(_raw,"success=yes")
        AND auid!="0"
        AND auid!="4294967295",
    "host_command_execution",
    true(), null()
)
| where isnotnull(signal)
| eval audit_session=if(
    signal="host_ssh_session_created" OR signal="host_command_execution",
    ses, null()
)
| eval endpoint="splunk-server"
| bin _time span=5m
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    dc(audit_session) as audit_session_count
    values(audit_session) as sessions
    values(ssh_src_ip) as source_ips
    min(_time) as first_seen
    max(_time) as last_seen
    by _time endpoint
| where signal_count >= 2
| where audit_session_count <= 1
| eval combined_confidence=case(
    signal_count=3, 0.97,
    signal_count=2, 0.85,
    true(), 0.70
)
| where combined_confidence >= 0.75
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence endpoint signal_count signals_detected sessions source_ips first_seen last_seen
"""

    check3_results = connector.search(check3_query)
    evidence["checks"]["ssh_lateral_movement"] = {
        "description": "SSH lateral movement — Zeek inbound SSH + auditd session creation + command execution",
        "query": check3_query.strip(),
        "result_count": len(check3_results),
        "results": check3_results,
        "severity": "CRITICAL" if len(check3_results) > 0 else "NONE",
        "mitre": ["T1021.004"],
        "interpretation": (
            f"CONFIRMED — {len(check3_results)} lateral movement session(s) detected. "
            "SSH connection from lab host confirmed by both Zeek network layer and auditd host layer in same audit session."
            if len(check3_results) > 0
            else "No SSH lateral movement detected."
        )
    }

    # ------------------------------------------------------------------ #
    # CHECK 4 — Combined Kill Chain Score
    # Port scan + SSH access + command execution from same attacker IP
    # ------------------------------------------------------------------ #
    check4_query = f"""
search index=main (sourcetype=zeek_conn OR sourcetype=linux_audit) earliest={earliest} latest={latest}
| rex field=_raw "\\"id\\.orig_h\\":\\"(?P<orig_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_h\\":\\"(?P<resp_ip>[^\\"]+)\\""
| rex field=_raw "\\"id\\.resp_p\\":(?P<resp_port>\\d+)"
| rex field=_raw "addr=(?P<ssh_src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
| rex field=_raw "auid=(?P<auid>\\d+)"
| rex field=_raw "ses=(?P<ses>\\d+)"
| eval attacker_ip=case(
    sourcetype="zeek_conn", orig_ip,
    sourcetype="linux_audit" AND match(_raw,"type=USER_START"), ssh_src_ip,
    true(), null()
)
| eval signal=case(
    sourcetype="zeek_conn"
        AND match(orig_ip,"^10\\.10\\.10\\.")
        AND match(resp_ip,"^10\\.10\\.10\\.")
        AND proto="tcp"
        AND (conn_state="S0" OR conn_state="REJ" OR conn_state="RSTOS0"),
    "network_port_scan",
    sourcetype="zeek_conn"
        AND match(orig_ip,"^10\\.10\\.10\\.")
        AND resp_ip="10.10.10.198"
        AND resp_port="22"
        AND proto="tcp"
        AND (conn_state="SF" OR conn_state="S1" OR conn_state="OTH"),
    "network_ssh_inbound",
    sourcetype="linux_audit"
        AND match(_raw,"type=USER_START")
        AND match(_raw,"exe=\\"/usr/sbin/sshd\\"")
        AND match(_raw,"res=success")
        AND match(ssh_src_ip,"^10\\.10\\.10\\."),
    "host_ssh_session_created",
    sourcetype="linux_audit"
        AND match(_raw,"key=\\"proc_exec\\"")
        AND match(_raw,"success=yes")
        AND auid!="0"
        AND auid!="4294967295",
    "host_command_execution",
    true(), null()
)
| where isnotnull(signal)
| eval audit_session=if(
    signal="host_ssh_session_created" OR signal="host_command_execution",
    ses, null()
)
| eval technique_weight=case(
    signal="network_port_scan", 0.80,
    signal="network_ssh_inbound", 0.85,
    signal="host_ssh_session_created", 0.90,
    signal="host_command_execution", 0.75,
    true(), 0.50
)
| bin _time span=30m
| stats
    dc(signal) as signal_count
    values(signal) as signals_detected
    dc(audit_session) as audit_session_count
    values(audit_session) as sessions
    sum(technique_weight) as raw_score
    values(ssh_src_ip) as ssh_sources
    min(_time) as first_seen
    max(_time) as last_seen
    by _time attacker_ip
| where signal_count >= 3
| where audit_session_count <= 1
| eval combined_confidence=min(round(raw_score/signal_count * 1.10, 2), 1.0)
| where combined_confidence >= 0.80
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table combined_confidence attacker_ip signal_count signals_detected sessions ssh_sources first_seen last_seen
"""

    check4_results = connector.search(check4_query)
    evidence["checks"]["kill_chain_correlation"] = {
        "description": "Complete kill chain — port scan + SSH access + command execution from same attacker IP",
        "query": check4_query.strip(),
        "result_count": len(check4_results),
        "results": check4_results,
        "severity": "CRITICAL" if len(check4_results) > 0 else "NONE",
        "mitre": ["T1046", "T1021.004", "T1059"],
        "interpretation": (
            f"CONFIRMED — {len(check4_results)} complete attack chain(s) detected. "
            "Same attacker IP responsible for reconnaissance, network access, and host command execution. Immediate response required."
            if len(check4_results) > 0
            else "No complete attack chain detected in window."
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

    if checks.get("kill_chain_correlation", {}).get("result_count", 0) > 0:
        actions.append("IMMEDIATE: Complete attack chain confirmed — isolate affected host from network")
        actions.append("IMMEDIATE: Review attacker_ip — block at OPNsense firewall")
        actions.append("IMMEDIATE: Check auditd for all commands executed in the SSH session")
        actions.append("IMMEDIATE: Review /tmp and /dev/shm for staged tools or exfiltrated data")

    if checks.get("ssh_lateral_movement", {}).get("result_count", 0) > 0:
        actions.append("SHORT TERM: SSH session from internal host confirmed — check source host for compromise")
        actions.append("SHORT TERM: Review session commands in auditd proc_exec records")
        actions.append("SHORT TERM: Check for persistence mechanisms installed during session")

    if checks.get("port_scan", {}).get("result_count", 0) > 0:
        actions.append("INVESTIGATE: Port scan detected — identify source host and whether it is compromised")
        actions.append("INVESTIGATE: Correlate scan timing with any recent suspicious activity on source host")

    if not actions:
        actions.append("No lateral movement confirmed — continue monitoring")

    return actions


def _get_kill_chain(checks: dict) -> list:
    phases = []

    if checks.get("port_scan", {}).get("result_count", 0) > 0:
        phases.append("Reconnaissance — network port scanning detected")

    if checks.get("host_discovery", {}).get("result_count", 0) > 0:
        phases.append("Discovery — internal host enumeration detected")

    if checks.get("ssh_lateral_movement", {}).get("result_count", 0) > 0:
        phases.append("Lateral Movement — SSH session from internal host to target confirmed")

    if checks.get("kill_chain_correlation", {}).get("result_count", 0) > 0:
        phases.append("Complete Chain — recon → access → execution confirmed from single attacker IP")

    return phases if phases else ["No kill chain phases confirmed"]


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Combined Lateral Movement Attack Chain Detected"
    import json
    results = run(alert)
    print(json.dumps(results, indent=2, default=str))
