"""
BLIP-AI Playbook: Linux Privilege Escalation
=============================================
Based on manual detection project:
Taylor-Cybersecurity-Homelab/Projects/Domain-01-Linux-SIEM/02-Privilege-Escalation

MITRE ATT&CK:
- T1548.003  Sudo and Sudo Caching Abuse
- T1548.001  Setuid and Setgid
- T1053.003  Scheduled Task/Job: Cron
- T1552.001  Credentials in Files
- T1070.002  Clear Linux Logs
- T1105      Ingress Tool Transfer
- T1136.001  Create Account

Version: 1.0
Author: BLIP-AI / Taylor Glass
"""

PLAYBOOK = {
    "name": "Linux Privilege Escalation",
    "version": "1.0",
    "mitre_techniques": [
        "T1548.003", "T1548.001", "T1053.003",
        "T1552.001", "T1070.002", "T1105", "T1136.001"
    ],
    "trigger_conditions": [
        "euid=0 from non-root process",
        "SUID enumeration behavior detected",
        "Shadow file direct read by non-system process",
        "LOLBin executed under sudo",
        "Log file deletion detected",
        "Backdoor account created"
    ],
    "required_sources": ["linux_audit"],
    "confidence_threshold": 0.85,
    "auto_response_threshold": 0.90
}

INVESTIGATION_STEPS = [
    {
        "step": 1,
        "name": "SUID Enumeration Detection",
        "description": "Behavioral scoring of SUID binary discovery. "
                       "Catches multiple enumeration syntaxes. "
                       "Single commands score MEDIUM. Multiple techniques score HIGH.",
        "phase": "reconnaissance",
        "splunk_query": """
            index=main sourcetype=linux_audit type=EXECVE earliest=-15m
            | rex field=_raw "a0=\\"(?P<a0>[^\\"]+)\\""
            | rex field=_raw "a1=\\"(?P<a1>[^\\"]+)\\""
            | rex field=_raw "a2=\\"(?P<a2>[^\\"]+)\\""
            | eval full_cmd=coalesce(a0,"")." ".coalesce(a1,"")." ".coalesce(a2,"")
            | eval score=0
            | eval score=if(match(full_cmd,"find") AND match(full_cmd,"-perm"), score+3, score)
            | eval score=if(match(full_cmd,"4000") OR match(full_cmd,"u=s"), score+3, score)
            | where score >= 3
            | stats sum(score) as total_score values(full_cmd) as commands by host
            | eval risk=case(total_score>=8,"HIGH",total_score>=5,"MEDIUM",true(),"LOW")
            | table host total_score risk commands
        """,
        "confidence_weight": 0.20,
        "what_to_look_for": "Non-root user searching for SUID binaries"
    },
    {
        "step": 2,
        "name": "Sudo LOLBin Execution",
        "description": "Shell-capable binaries executed under sudo. "
                       "vim, python, perl, find, bash all carry escalation risk.",
        "phase": "exploitation",
        "splunk_query": """
            index=main sourcetype=linux_audit type=EXECVE earliest=-15m
            | rex field=_raw "a0=\\"(?P<a0>[^\\"]+)\\""
            | rex field=_raw "a1=\\"(?P<a1>[^\\"]+)\\""
            | eval binary=mvindex(split(a1,"/"),-1)
            | where a0="sudo"
            | eval score=case(
                match(binary,"^(vim|vi|nano)$"), 5,
                match(binary,"^(python|python3|perl|ruby)$"), 6,
                match(binary,"^(bash|sh|zsh)$"), 7,
                match(binary,"^(find|awk|nmap)$"), 5,
                true(), 0)
            | where score > 0
            | stats sum(score) as total_score values(a1) as binaries by host
            | eval risk=case(total_score>=8,"CRITICAL",total_score>=5,"HIGH",true(),"MEDIUM")
            | table host total_score risk binaries
        """,
        "confidence_weight": 0.25,
        "what_to_look_for": "Shell-capable binary under sudo especially with shell escape flags"
    },
    {
        "step": 3,
        "name": "Escalation Confirmation — euid=0",
        "description": "THE key detection. Non-root user spawning processes "
                       "with effective UID 0. Technique-agnostic — catches sudo abuse, "
                       "SUID exploitation, and cron attacks simultaneously. "
                       "Cannot be spoofed at kernel level.",
        "phase": "escalation_confirmed",
        "splunk_query": """
            index=main sourcetype=linux_audit type=SYSCALL earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "(?i)euid[=:\\"](?P<euid>\\d+)"
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where euid="0" AND auid!="unset" AND auid!="root" AND auid!="4294967295"
            | where success="yes"
            | eval binary=mvindex(split(exe,"/"),-1)
            | where binary!="cron" AND binary!="sshd" AND binary!="passwd"
            | eval technique=case(
                binary="find", "SUID Binary Exploitation",
                binary="bash" OR binary="sh", "Direct Shell Spawn",
                binary="sudo", "SUDO LOLBin Abuse",
                binary="python3" OR binary="perl", "Interpreter Escalation",
                true(), "Unknown — Investigate Immediately")
            | stats count values(exe) as processes values(technique) as techniques by auid host
            | table auid host count processes techniques
        """,
        "confidence_weight": 0.40,
        "what_to_look_for": "ANY result — euid=0 from labadmin is escalation confirmed",
        "verdict_trigger": True,
        "verdict_if_results": "CRITICAL — Privilege escalation confirmed"
    },
    {
        "step": 4,
        "name": "Credential Harvesting",
        "description": "Direct reads of /etc/shadow by non-system processes. "
                       "Filters 1600+ daily PAM noise events via comm field.",
        "phase": "post_exploitation",
        "splunk_query": """
            index=main sourcetype=linux_audit key="shadow_access" earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where auid!="unset" AND auid!="4294967295"
            | eval binary=mvindex(split(exe,"/"),-1)
            | where binary!="login" AND binary!="passwd" AND binary!="sshd" AND binary!="sudo"
            | stats count values(exe) as processes values(success) as results by auid host
            | table auid host count processes results
        """,
        "confidence_weight": 0.20,
        "what_to_look_for": "labadmin reading /etc/shadow via cat, less, or python"
    },
    {
        "step": 5,
        "name": "Log Tampering — Anti-Forensics",
        "description": "Deletion of log files after escalation. "
                       "Log deletion is strong indicator escalation succeeded "
                       "and attacker is covering tracks.",
        "phase": "post_exploitation",
        "splunk_query": """
            index=main sourcetype=linux_audit key="log_tampering" type=SYSCALL earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where auid!="unset" AND auid!="4294967295"
            | where success="yes"
            | where comm="rm" OR comm="shred" OR comm="truncate"
            | stats count values(comm) as tools by auid host
            | table auid host count tools
        """,
        "confidence_weight": 0.30,
        "what_to_look_for": "rm or shred against /var/log files — definitive anti-forensics"
    }
]

RISK_SCORING = {
    "base_score": 0.0,
    "confidence_factors": [
        {
            "name": "suid_enumeration",
            "weight": 0.20,
            "score_if_high": 0.20,
            "score_if_medium": 0.12
        },
        {
            "name": "sudo_lolbin",
            "weight": 0.25,
            "score_if_critical": 0.25,
            "score_if_high": 0.18
        },
        {
            "name": "escalation_confirmed",
            "weight": 0.40,
            "score_if_any_result": 0.40,
            "note": "Single highest-weight factor — any result drives confidence above 0.85"
        },
        {
            "name": "credential_harvesting",
            "weight": 0.20,
            "score_if_confirmed": 0.20
        },
        {
            "name": "log_tampering",
            "weight": 0.30,
            "score_if_detected": 0.30,
            "note": "Combined with escalation pushes confidence above 0.90 auto-response threshold"
        }
    ],
    "autonomous_response_threshold": 0.90,
    "analyst_review_threshold": 0.70
}

VERDICT_LOGIC = {
    "True Positive — Critical": {
        "conditions": [
            "escalation_confirmed = True",
            "AND (log_tampering = True OR credential_harvesting = True)"
        ],
        "confidence": "0.95+",
        "auto_response": "block_ip_opnsense + create_thehive_case + generate_pdf_report"
    },
    "True Positive — High": {
        "conditions": [
            "escalation_confirmed = True",
            "AND confidence >= 0.85"
        ],
        "confidence": "0.85-0.94",
        "auto_response": "create_thehive_case + generate_pdf_report"
    },
    "False Positive": {
        "conditions": [
            "exe in (apt, dpkg, snap, passwd)",
            "OR activity in maintenance_window"
        ],
        "confidence": "< 0.30",
        "auto_response": "suppress_alert"
    }
}

FALSE_POSITIVE_RULES = [
    {
        "rule": "package_manager",
        "description": "apt/dpkg running as root during package installation",
        "conditions": "euid=0 AND binary in (apt, apt-get, dpkg, snap)",
        "action": "suppress_alert"
    },
    {
        "rule": "shadow_pam",
        "description": "PAM authentication touching /etc/shadow",
        "conditions": "comm in (sudo, sshd, cron, login, passwd)",
        "action": "suppress_shadow_alert",
        "note": "1600+ daily PAM events filtered by comm field"
    }
]

RESPONSE_ACTIONS = {
    "immediate": [
        "Take Proxmox VM snapshot for forensic preservation",
        "Check /etc/passwd for new backdoor accounts",
        "Review currently active sessions: who -a"
    ],
    "investigation": [
        "Audit sudoers for NOPASSWD entries: sudo grep -r NOPASSWD /etc/sudoers*",
        "Check SUID binaries: find / -perm -4000 -type f 2>/dev/null",
        "Review root crontab: sudo crontab -l",
        "Check /root/.ssh/authorized_keys for new SSH keys"
    ],
    "remediation": [
        "Remove NOPASSWD entries from sudoers",
        "Remove SUID bit from non-essential binaries: sudo chmod u-s /usr/bin/find",
        "Rotate all user credentials",
        "Implement file integrity monitoring"
    ]
}

PLAYBOOK_CONNECTIONS = {
    "preceded_by": [
        {
            "playbook": "brute_force.py",
            "reason": "SSH brute force often precedes escalation",
            "confidence_modifier": "+0.15 if same IP in brute force within 24h"
        },
        {
            "playbook": "network_recon.py",
            "reason": "Port scan before escalation indicates coordinated attack",
            "confidence_modifier": "+0.10 if same IP performed recon"
        }
    ],
    "escalates_to": [
        {
            "playbook": "persistence.py",
            "trigger": "escalation_confirmed = True",
            "reason": "Attacker will plant persistence after getting root"
        }
    ]
}

BASELINE_METRICS = {
    "manual_detection": {
        "events_analyzed": 857162,
        "mttd_minutes": 3.17,
        "detection_rate": 1.0,
        "false_positive_rate": 0.0,
        "vulnerabilities_planted": 3,
        "vulnerabilities_patched": 3
    }
}

CYSA_CONNECTIONS = {
    "1.1": "Log Configuration — 17 custom audit rules",
    "1.2": "LOLBins — shell-capable binaries abused under sudo",
    "1.2": "Anomalous Activity — euid=0 from non-root is kernel anomaly",
    "1.3": "SIEM SPL — behavioral scoring across 857k events",
    "1.5": "Alert Tuning — FP rate reduced from 95% to 0%",
    "4.2": "MTTD — 3 minutes 10 seconds"
}
