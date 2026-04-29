"""
BLIP-AI Playbook: Network Reconnaissance Detection
===================================================
Based on manual detection project:
Taylor-Cybersecurity-Homelab/Projects/Domain-02-Network-Security/02-Network-Reconnaissance-Detection

MITRE ATT&CK:
- T1046  Network Service Discovery

Version: 2.0
Status: Active
Last Updated: 2026-04
Author: BLIP-AI / Taylor Glass

Changelog:
- V1.0: Basic port scan detection from Project 02 OPNsense Network Visibility
- V2.0: Full three-layer behavioral detection — volume, intent, and campaign persistence
"""

PLAYBOOK = {
    "name": "Network Reconnaissance Detection",
    "version": "2.0",
    "mitre_techniques": ["T1046"],
    "trigger_conditions": [
        "Single source IP hitting 10+ unique destination ports in 5 minute window",
        "Source IP probing 2+ sensitive service ports",
        "Same source IP appearing in 2+ scan windows within 4 hour period"
    ],
    "required_sources": ["syslog"],
    "log_origin": "OPNsense filterlog via UDP 5514",
    "confidence_threshold": 0.75,
    "auto_response_threshold": 0.90,
    "precedes_exploitation": True
}

RECON_LIFECYCLE = {
    "phases": [
        {
            "phase": "Discovery",
            "description": "Attacker identifies live hosts on the network",
            "detection": "Detection 1 — port count threshold"
        },
        {
            "phase": "Enumeration",
            "description": "Attacker maps open ports and services on identified hosts",
            "detection": "Detection 1 — volume based port scan detection"
        },
        {
            "phase": "Targeting",
            "description": "Attacker identifies high-value services to exploit",
            "detection": "Detection 2 — sensitive service enumeration"
        },
        {
            "phase": "Campaign",
            "description": "Attacker conducts repeated reconnaissance over time",
            "detection": "Detection 3 — repeated reconnaissance campaign"
        }
    ]
}
INVESTIGATION_STEPS = [
    {
        "step": 1,
        "name": "Port Scan Detection — Volume Based",
        "description": "Count unique destination ports per source IP per 5 minute window. "
                       "The behavioral signature of port scanning regardless of tool used. "
                       "Normal traffic hits 2-5 unique ports. A scan hits 10-1000+. "
                       "Tool-agnostic — Nmap, Masscan, custom scripts all produce same pattern.",
        "phase": "enumeration",
        "splunk_query": """
            index=main sourcetype=syslog earliest=-15m
            | rex field=_raw "(?P<src_ip>10\\.10\\.10\\.\\d+),(?P<dst_ip>[\\d.]+),(?P<src_port>\\d+),(?P<dst_port>\\d+)"
            | where isnotnull(src_ip) AND isnotnull(dst_port)
            | bin _time span=5m
            | stats dc(dst_port) as unique_ports count as total_packets by src_ip dst_ip _time
            | where unique_ports >= 10
            | eval risk_level=case(
                unique_ports>=100, "CRITICAL — Aggressive full port scan",
                unique_ports>=50,  "HIGH — Port scan detected",
                unique_ports>=20,  "MEDIUM — Possible port scan",
                unique_ports>=10,  "LOW — Suspicious port activity")
            | eval scan_type=case(
                unique_ports>=100, "Full scan — Nmap aggressive or similar",
                unique_ports>=50,  "Service scan — Top ports enumerated",
                unique_ports>=20,  "Targeted scan — Specific port range",
                unique_ports>=10,  "Probe — Initial reconnaissance")
            | table _time src_ip dst_ip unique_ports total_packets scan_type risk_level
            | sort -unique_ports
        """,
        "confidence_weight": 0.35,
        "what_to_look_for": "Any source IP with unique_ports >= 10 in a 5 minute window",
        "false_positive_note": "Authorized vulnerability scanners — add to allowlist. "
                               "Threshold of 10 eliminates virtually all legitimate traffic.",
        "threshold_calibration": {
            "normal_traffic": "2-5 unique ports per session",
            "developer_testing": "5-10 unique ports",
            "port_scan": "10-1000+ unique ports"
        }
    },
    {
        "step": 2,
        "name": "Sensitive Service Enumeration — Intent Based",
        "description": "Detect probing of high-value service ports regardless of scan volume. "
                       "A patient attacker checking only SSH, RDP, and SMB hits 3 ports — "
                       "evading volume detection entirely. "
                       "This detection catches them by recognizing WHICH ports they target.",
        "phase": "targeting",
        "splunk_query": """
            index=main sourcetype=syslog earliest=-15m
            | rex field=_raw "(?P<src_ip>10\\.10\\.10\\.\\d+),(?P<dst_ip>[\\d.]+),(?P<src_port>\\d+),(?P<dst_port>\\d+)"
            | where isnotnull(src_ip) AND isnotnull(dst_port)
            | eval dst_port=tonumber(dst_port)
            | eval sensitive_port=case(
                dst_port=22,   "SSH",
                dst_port=23,   "Telnet",
                dst_port=25,   "SMTP",
                dst_port=53,   "DNS",
                dst_port=80,   "HTTP",
                dst_port=443,  "HTTPS",
                dst_port=445,  "SMB",
                dst_port=3389, "RDP",
                dst_port=5432, "Postgres",
                dst_port=8000, "Splunk Web",
                dst_port=9997, "Splunk Forwarder",
                dst_port=3306, "MySQL",
                dst_port=21,   "FTP",
                dst_port=5900, "VNC")
            | where isnotnull(sensitive_port)
            | stats count values(sensitive_port) as services_probed
                dc(sensitive_port) as unique_services by src_ip dst_ip
            | where unique_services >= 2
            | eval risk_level=case(
                unique_services>=6, "CRITICAL — Broad sensitive service enumeration",
                unique_services>=4, "HIGH — Multiple high-value services probed",
                unique_services>=2, "MEDIUM — Sensitive service reconnaissance")
            | table src_ip dst_ip unique_services services_probed count risk_level
            | sort -unique_services
        """,
        "confidence_weight": 0.25,
        "what_to_look_for": "Source IP probing 2+ sensitive ports — especially RDP+SMB+SSH combinations",
        "attack_intent_mapping": {
            "SSH + RDP": "Remote access establishment",
            "SMB + RDP": "Windows lateral movement preparation",
            "SSH + Splunk Web": "Security tool targeting — attacker going after detection infrastructure"
        },
        "false_positive_note": "Single sensitive port is expected. "
                               "Two or more from same source indicates enumeration."
    },
    {
        "step": 3,
        "name": "Repeated Reconnaissance Campaign — Persistence Based",
        "description": "Same source IP appearing across multiple scan windows over time. "
                       "Single scan could be accidental. "
                       "Same IP scanning repeatedly over hours is a deliberate campaign. "
                       "campaign_summary feeds directly into BLIP-AI investigation reports.",
        "phase": "campaign",
        "splunk_query": """
            index=main sourcetype=syslog earliest=-4h
            | rex field=_raw "(?P<src_ip>10\\.10\\.10\\.\\d+),(?P<dst_ip>[\\d.]+),(?P<src_port>\\d+),(?P<dst_port>\\d+)"
            | where isnotnull(src_ip) AND isnotnull(dst_port)
            | bin _time span=5m
            | stats dc(dst_port) as unique_ports by src_ip dst_ip _time
            | where unique_ports >= 10
            | stats count as scan_windows avg(unique_ports) as avg_ports
                dc(dst_ip) as targets_scanned by src_ip
            | where scan_windows >= 2
            | eval risk_level=case(
                scan_windows>=5, "CRITICAL — Sustained reconnaissance campaign",
                scan_windows>=3, "HIGH — Repeated scanning behavior detected",
                scan_windows>=2, "MEDIUM — Multiple scan windows observed")
            | eval campaign_summary=src_ip." scanned ".tostring(round(avg_ports,0)).
                " avg ports across ".tostring(scan_windows).
                " windows targeting ".tostring(targets_scanned)." host(s)"
            | table src_ip scan_windows avg_ports targets_scanned campaign_summary risk_level
            | sort -scan_windows
        """,
        "confidence_weight": 0.30,
        "what_to_look_for": "Same source IP in 3+ scan windows — deliberate persistent campaign",
        "blip_ai_output": "campaign_summary field feeds directly into investigation report narrative",
        "apt_indicator": "5+ scan windows from same IP over 4 hours = APT-level patience",
        "false_positive_note": "Authorized vulnerability scanners run on schedules — add to allowlist."
    }
]

RISK_SCORING = {
    "base_score": 0.0,
    "confidence_factors": [
        {
            "name": "port_scan_volume",
            "description": "High unique port count from single source",
            "weight": 0.35,
            "score_if_critical": 0.35,
            "score_if_high": 0.25,
            "score_if_medium": 0.15
        },
        {
            "name": "sensitive_service_enumeration",
            "description": "High-value service ports specifically targeted",
            "weight": 0.25,
            "score_if_critical": 0.25,
            "score_if_high": 0.18,
            "score_if_medium": 0.10,
            "note": "Port selection reveals intent — weighted higher than volume alone"
        },
        {
            "name": "repeated_campaign",
            "description": "Same source IP in multiple scan windows",
            "weight": 0.30,
            "score_if_critical": 0.30,
            "score_if_high": 0.22,
            "note": "Persistence is strong APT indicator — highest weight"
        },
        {
            "name": "followed_by_exploitation",
            "description": "Recon source IP matches subsequent escalation alert",
            "weight": 0.25,
            "score_if_true": 0.25,
            "note": "Recon followed by exploitation confirms attack chain"
        }
    ],
    "autonomous_response_threshold": 0.90,
    "analyst_review_threshold": 0.70
}

VERDICT_LOGIC = {
    "True Positive — Critical": {
        "conditions": [
            "repeated_campaign = CRITICAL (scan_windows >= 5)",
            "OR (port_scan_volume = CRITICAL AND followed_by_exploitation = True)"
        ],
        "confidence": "0.90+",
        "auto_response": "block_ip_opnsense + create_thehive_case + generate_pdf_report"
    },
    "True Positive — High": {
        "conditions": [
            "port_scan_volume = HIGH OR CRITICAL",
            "AND confidence >= 0.70"
        ],
        "confidence": "0.70-0.89",
        "auto_response": "create_thehive_case"
    },
    "False Positive": {
        "conditions": [
            "source_ip in authorized_scanner_allowlist",
            "OR activity during scheduled vulnerability scan window"
        ],
        "confidence": "< 0.30",
        "auto_response": "suppress_alert"
    }
}

FALSE_POSITIVE_RULES = [
    {
        "rule": "authorized_vulnerability_scanner",
        "description": "Known scanner running scheduled assessment",
        "conditions": "source_ip in authorized_scanner_list",
        "action": "suppress_alert",
        "note": "Add Nessus, OpenVAS scanner IPs to this list"
    },
    {
        "rule": "network_monitoring_tool",
        "description": "Nagios, PRTG checking service availability",
        "conditions": "source_ip in monitoring_tool_list AND unique_ports <= 20",
        "action": "suppress_alert"
    }
]

ATTACK_CHAIN_CORRELATION = {
    "description": "Cross-playbook correlation for BLIP-AI V1 investigation loop",
    "correlation_query": """
        index=main (sourcetype=syslog OR sourcetype=linux_secure OR sourcetype=linux_audit)
        | rex field=_raw "(?P<src_ip>10\\.10\\.10\\.\\d+)"
        | eval stage=case(
            sourcetype="syslog", "1-Reconnaissance",
            sourcetype="linux_secure" AND match(_raw,"Failed password"), "2-Brute Force",
            sourcetype="linux_audit" AND match(_raw,"euid=0"), "3-Escalation",
            sourcetype="linux_audit" AND match(_raw,"ssh_key|cron_mod"), "4-Persistence",
            true(), "Unknown")
        | stats dc(stage) as stages values(stage) as kill_chain by src_ip
        | where stages >= 2
        | eval chain_confidence=case(
            stages>=4, "CRITICAL — Full kill chain",
            stages>=3, "HIGH — Multi-stage attack",
            stages>=2, "MEDIUM — Attack progression",
            true(), "LOW")
        | table src_ip stages kill_chain chain_confidence
        | sort -stages
    """,
    "note": "Foundation of BLIP-AI V1 autonomous investigation loop"
}

RESPONSE_ACTIONS = {
    "immediate": [
        "Block source IP at OPNsense firewall if confidence >= 0.90",
        "Check if source IP appears in privilege escalation alerts",
        "Cross-reference source IP with auth.log for login attempts"
    ],
    "investigation": [
        "Review full OPNsense filterlog for source IP across all time",
        "Identify all services probed and their current patch status",
        "Search threat intelligence feeds for source IP reputation"
    ],
    "prevention": [
        "Implement port knocking for SSH access",
        "Deploy honeypot ports to catch low-volume targeted scans",
        "Enable geo-blocking for unexpected source countries"
    ]
}

PLAYBOOK_CONNECTIONS = {
    "precedes": [
        {
            "playbook": "privilege_escalation.py",
            "reason": "Reconnaissance precedes exploitation — same IP in both confirms attack chain",
            "confidence_modifier": "+0.25 to escalation confidence if same IP recon within 24h"
        },
        {
            "playbook": "brute_force.py",
            "reason": "Port scan identifying SSH often precedes brute force",
            "confidence_modifier": "+0.20 to brute force confidence if same IP performed recon"
        }
    ],
    "informs": [
        {
            "playbook": "incident_response.py",
            "data_passed": "campaign_summary, services_probed, first_seen timestamp",
            "effect": "IR timeline starts from first recon event not first exploitation"
        }
    ]
}

BASELINE_METRICS = {
    "manual_detection": {
        "scan_techniques_simulated": 4,
        "detection_rules_built": 3,
        "total_syslog_events": 827553,
        "unique_ports_detected": 632,
        "total_scan_packets": 1748,
        "detection_rate": 1.0,
        "false_positive_rate": 0.0,
        "mitre_techniques": ["T1046"]
    }
}

CYSA_CONNECTIONS = {
    "1.1": "Log Configuration — OPNsense firewall logging rule deployed",
    "1.2": "Enumeration — port scanning as systematic network reconnaissance",
    "1.3": "SIEM SPL — three behavioral rules on firewall telemetry",
    "1.4": "Behavioral IOC — traffic pattern detection not signature matching",
    "1.4_b": "APT — repeated campaign detection for persistent reconnaissance",
    "2.1": "Discovery Scanning — port scanning as attack lifecycle discovery phase",
    "3.2": "Detection Phase — network detection before host exploitation begins",
    "4.2": "True Positive Rate — 100% across all four scan techniques"
}
