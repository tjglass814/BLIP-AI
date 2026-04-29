"""
BLIP-AI Playbook: SSH Brute Force Detection
============================================
Based on manual detection project:
Taylor-Cybersecurity-Homelab/Projects/Domain-01-Linux-SIEM/01-SSH-Brute-Force-Detection

MITRE ATT&CK:
- T1110     Brute Force
- T1078     Valid Accounts
- T1021.004 Remote Services: SSH

Version: 1.0
Author: BLIP-AI / Taylor Glass
"""

PLAYBOOK = {
    "name": "SSH Brute Force Detection",
    "version": "1.0",
    "mitre_techniques": ["T1110", "T1078", "T1021.004"],
    "trigger_conditions": [
        "More than 5 failed SSH login attempts from single source IP",
        "Rapid sequential authentication failures in short window"
    ],
    "required_sources": ["linux_secure"],
    "confidence_threshold": 0.75,
    "auto_response_threshold": 0.90
}

INVESTIGATION_STEPS = [
    {
        "step": 1,
        "name": "Brute Force Volume Detection",
        "description": "Count failed SSH attempts per source IP. "
                       "Threshold of 5+ failures flags brute force behavior. "
                       "Normal users generate 1-2 failures max.",
        "phase": "detection",
        "splunk_query": """
            index=main sourcetype=linux_secure "Failed password" earliest=-1h
            | rex field=_raw "Failed password for \\S+ from (?P<src_ip>\\d+.\\d+.\\d+.\\d+)"
            | stats count by src_ip
            | where count > 5
            | sort -count
        """,
        "confidence_weight": 0.40,
        "what_to_look_for": "Source IP with high failure count — especially 100+ attempts",
        "false_positive_note": "Misconfigured scripts or automation can cause false positives — "
                               "check if IP is in known admin allowlist"
    },
    {
        "step": 2,
        "name": "Breach Confirmation",
        "description": "Check for successful logins following brute force attempts. "
                       "A successful login after hundreds of failures indicates compromise.",
        "phase": "confirmation",
        "splunk_query": """
            index=main sourcetype=linux_secure
            ("Accepted password" OR "Accepted publickey") earliest=-1h
            | rex field=_raw "Accepted \\S+ for (?P<user>\\S+) from (?P<src_ip>\\d+.\\d+.\\d+.\\d+)"
            | stats count by src_ip user
            | sort -count
        """,
        "confidence_weight": 0.50,
        "what_to_look_for": "Accepted login from same IP that generated failures",
        "verdict_trigger": True,
        "verdict_if_results": "CRITICAL — Brute force succeeded — account compromised"
    },
    {
        "step": 3,
        "name": "Attack Timeline Correlation",
        "description": "Full activity correlation showing both failed and accepted "
                       "logins grouped by source IP for complete picture.",
        "phase": "correlation",
        "splunk_query": """
            index=main sourcetype=linux_secure earliest=-1h
            | rex field=_raw "(?:Failed password|Accepted password) for \\S+ from (?P<src_ip>\\d+.\\d+.\\d+.\\d+)"
            | stats count by src_ip
            | sort -count
        """,
        "confidence_weight": 0.10,
        "what_to_look_for": "Two distinct IPs — attack source vs legitimate admin source"
    }
]

RISK_SCORING = {
    "base_score": 0.0,
    "confidence_factors": [
        {
            "name": "high_volume_failures",
            "description": "100+ failed attempts from single IP",
            "weight": 0.40,
            "score_if_detected": 0.40
        },
        {
            "name": "successful_login_after_failures",
            "description": "Accepted login from brute force source IP",
            "weight": 0.50,
            "score_if_detected": 0.50
        },
        {
            "name": "off_hours_activity",
            "description": "Attack occurring outside business hours",
            "weight": 0.10,
            "score_if_detected": 0.10
        }
    ],
    "autonomous_response_threshold": 0.90,
    "analyst_review_threshold": 0.70
}

VERDICT_LOGIC = {
    "True Positive — Critical": {
        "conditions": [
            "successful_login_after_failures = True"
        ],
        "confidence": "0.90+",
        "auto_response": "block_ip_opnsense + create_thehive_case + generate_pdf_report"
    },
    "True Positive — High": {
        "conditions": [
            "failure_count >= 100",
            "AND no_successful_login"
        ],
        "confidence": "0.70-0.89",
        "auto_response": "create_thehive_case"
    },
    "False Positive": {
        "conditions": [
            "source_ip in admin_allowlist",
            "OR failure_count < 10"
        ],
        "confidence": "< 0.30",
        "auto_response": "suppress_alert"
    }
}

FALSE_POSITIVE_RULES = [
    {
        "rule": "known_admin_ip",
        "description": "Known admin workstation with misconfigured SSH key",
        "conditions": "source_ip in admin_allowlist AND failure_count < 20",
        "action": "suppress_alert"
    },
    {
        "rule": "monitoring_tool",
        "description": "Automated monitoring tool checking SSH availability",
        "conditions": "failure_count < 10 AND regular_interval_pattern",
        "action": "downgrade_severity"
    }
]

RESPONSE_ACTIONS = {
    "immediate": [
        "Block source IP at OPNsense firewall",
        "Check auth.log for successful logins from same IP",
        "Review currently active SSH sessions: who -a"
    ],
    "investigation": [
        "Determine targeted username — was it a valid account?",
        "Check if password was actually correct using auth.log",
        "Review source IP reputation in threat intelligence feeds"
    ],
    "remediation": [
        "Rotate credentials for targeted account",
        "Implement fail2ban or similar brute force protection",
        "Consider SSH key-only authentication — disable password auth",
        "Add MFA to SSH access"
    ]
}

PLAYBOOK_CONNECTIONS = {
    "escalates_to": [
        {
            "playbook": "privilege_escalation.py",
            "trigger": "successful_login_confirmed",
            "reason": "Successful brute force gives attacker foothold — escalation likely next"
        },
        {
            "playbook": "persistence.py",
            "trigger": "successful_login_confirmed",
            "reason": "Attacker will plant persistence after gaining access"
        }
    ],
    "preceded_by": [
        {
            "playbook": "network_recon.py",
            "reason": "Port scan identifying SSH port 22 often precedes brute force",
            "confidence_modifier": "+0.15 if same IP performed recon"
        }
    ]
}

BASELINE_METRICS = {
    "manual_detection": {
        "total_attempts": 2515,
        "attack_duration_minutes": 60,
        "successful_breaches": 0,
        "mttd_minutes": 5,
        "false_positive_rate": 0.0
    }
}

CYSA_CONNECTIONS = {
    "1.2": "Brute Force — credential based attack detection",
    "1.3": "SIEM SPL — regex field extraction from auth.log",
    "1.4": "Behavioral IOC — failure rate threshold detection",
    "3.2": "Detection Phase — automated alert within 5 minutes",
    "4.2": "MTTD — 5 minutes from attack start to alert"
}
