"""
BLIP-AI Playbook: Linux Persistence Detection
==============================================
Based on manual detection project:
Taylor-Cybersecurity-Homelab/Projects/Domain-01-Linux-SIEM/04-Persistence-Detection

MITRE ATT&CK:
- T1098.004  SSH Authorized Keys
- T1053.003  Scheduled Task/Job: Cron
- T1543.002  Create or Modify System Process: Systemd
- T1546.004  Event Triggered Execution: .bashrc

Version: 1.0
Author: BLIP-AI / Taylor Glass
"""

PLAYBOOK = {
    "name": "Linux Persistence Detection",
    "version": "1.0",
    "mitre_techniques": [
        "T1098.004", "T1053.003", "T1543.002", "T1546.004"
    ],
    "trigger_conditions": [
        "SSH authorized_keys directory modified",
        "Cron configuration modified by interactive user",
        "New systemd service file created AND systemctl executed",
        "Shell startup file modified by shell process"
    ],
    "required_sources": ["linux_audit"],
    "confidence_threshold": 0.85,
    "auto_response_threshold": 0.90
}

PERSISTENCE_LIFECYCLE = {
    "phases": [
        {
            "phase": "Creation",
            "description": "Attacker installs the persistence mechanism",
            "detection": "Detections 1-4 — file modification and execution events"
        },
        {
            "phase": "Execution",
            "description": "Persistence mechanism fires and delivers access",
            "detection": "pspy process monitoring + exfil_tool audit rules"
        },
        {
            "phase": "Maintenance",
            "description": "Repeated execution confirms ongoing attacker access",
            "detection": "Frequency-based analysis of execution events"
        },
        {
            "phase": "Removal",
            "description": "Attacker cleans up to avoid detection",
            "detection": "Same audit keys catching removal as creation"
        }
    ]
}

INVESTIGATION_STEPS = [
    {
        "step": 1,
        "name": "SSH Key Modification",
        "description": "Detect SSH authorized_keys directory modification. "
                       "Clusters chmod, script execution, and keyless login "
                       "into single persistence installation signal.",
        "phase": "creation",
        "splunk_query": """
            index=main sourcetype=linux_audit key="ssh_key_modification" earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
            | where success="yes"
            | eval binary=mvindex(split(exe,"/"),-1)
            | where binary!="sshd"
            | eval suspicion=case(
                binary="ssh", "SSH keyless login — possible backdoor key in use",
                binary="chmod" OR binary="chown", "SSH directory permission change",
                binary="sh" OR binary="dash" OR binary="bash", "Script modifying SSH config",
                true(), "Unknown SSH directory modification")
            | stats count values(exe) as tools values(suspicion) as indicators by auid host
            | eval risk=case(
                mvfind(indicators,"keyless login")>=0, "HIGH",
                mvfind(indicators,"Script modifying")>=0, "HIGH",
                true(), "MEDIUM")
            | table auid host count tools indicators risk
        """,
        "confidence_weight": 0.25,
        "what_to_look_for": "chmod + script writing + keyless login sequence from same user",
        "host_verification": "cat ~/.ssh/authorized_keys — check for keys not belonging to known admins"
    },
    {
        "step": 2,
        "name": "Cron Persistence — Modification",
        "description": "Detect modification of cron configuration files. "
                       "Searches raw audit records for reverse shell patterns.",
        "phase": "creation",
        "splunk_query": """
            index=main sourcetype=linux_audit key="cron_modification" earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
            | where isnotnull(success)
            | eval suspicious=if(
                match(_raw,"dev/tcp|nc |bash -i|curl|wget|python|perl"),
                "YES — Reverse shell detected", "NO")
            | stats count values(comm) as tools values(suspicious) as content by auid host
            | eval risk=case(
                like(content,"YES%"), "CRITICAL",
                true(), "HIGH")
            | table auid host count tools content risk
        """,
        "confidence_weight": 0.20,
        "what_to_look_for": "Interactive user running crontab — especially with reverse shell content",
        "host_verification": "sudo crontab -l — check for entries with dev/tcp, nc, bash -i"
    },
    {
        "step": 3,
        "name": "Cron Persistence — Execution",
        "description": "Detect direct execution of the crontab binary. "
                       "Medium alone — escalates when correlated with modification.",
        "phase": "creation",
        "splunk_query": """
            index=main sourcetype=linux_audit key="cron_exec" earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
            | where isnotnull(auid) AND auid!="unset" AND auid!="4294967295"
            | stats count values(comm) as tools by auid host
            | eval risk="MEDIUM — Cron execution observed (context required)"
            | table auid host count tools risk
        """,
        "confidence_weight": 0.15,
        "correlation_note": "Escalates to HIGH when cron_modification also fired from same host"
    },
    {
        "step": 4,
        "name": "Systemd Service Backdoor",
        "description": "Detect new service file creation AND systemctl execution. "
                       "sources_triggered=2 confirms complete persistence installation. "
                       "Legitimate services are symlinks — real files are suspicious.",
        "phase": "creation",
        "splunk_query": """
            index=main sourcetype=linux_audit
            (key="systemd_modification" OR key="systemd_exec") earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where isnotnull(auid) AND auid!="unset" AND auid!="4294967295"
            | where success="yes" OR success="1"
            | bin _time span=5m
            | eval binary=mvindex(split(exe,"/"),-1)
            | eval signal=case(
                key="systemd_modification" AND (binary="nano" OR binary="vim"),
                    "Service file created via text editor",
                key="systemd_exec" AND binary="systemctl",
                    "systemctl executed by interactive user",
                true(), "Unknown systemd activity")
            | stats count values(signal) as signals dc(key) as sources_triggered by auid host _time
            | eval risk=case(
                sources_triggered>=2, "CRITICAL — Persistence confirmed",
                true(), "HIGH")
            | table _time auid host signals sources_triggered risk
        """,
        "confidence_weight": 0.30,
        "what_to_look_for": "sources_triggered=2 — file creation AND systemctl in same 5 minute window",
        "host_verification": "sudo ls -la /etc/systemd/system/*.service — real files vs symlinks"
    },
    {
        "step": 5,
        "name": "Shell Startup File Modification",
        "description": "Detect modification of .bashrc and shell startup files. "
                       "Fires every time legitimate user logs in — "
                       "the harder the admin works the more shells attacker receives.",
        "phase": "creation",
        "splunk_query": """
            index=main sourcetype=linux_audit key="startup_modification" earliest=-15m
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where isnotnull(auid) AND auid!="unset" AND auid!="4294967295"
            | where success="yes" OR success="1"
            | eval binary=mvindex(split(exe,"/"),-1)
            | eval signal=case(
                binary="bash" OR binary="sh", "Shell writing to startup file",
                binary="nano" OR binary="vim", "Text editor modifying startup file",
                true(), "Unknown startup modification")
            | eval reverse_shell=if(
                match(_raw,"dev/tcp|nc |bash -i|curl|wget|eval|mkfifo"),1,0)
            | stats count values(signal) as signals sum(reverse_shell) as shell_indicators by auid host
            | eval risk=case(
                shell_indicators>0, "CRITICAL",
                like(signals,"%Shell writing%"), "HIGH",
                true(), "MEDIUM")
            | table auid host count signals shell_indicators risk
        """,
        "confidence_weight": 0.20,
        "what_to_look_for": "bash process writing to .bashrc",
        "host_verification": "tail -5 ~/.bashrc — check for reverse shell injection"
    }
]

RISK_SCORING = {
    "base_score": 0.0,
    "confidence_factors": [
        {"name": "ssh_key_modification", "weight": 0.25},
        {"name": "cron_modification", "weight": 0.20},
        {"name": "cron_execution", "weight": 0.15},
        {"name": "systemd_persistence", "weight": 0.30},
        {"name": "startup_file_modification", "weight": 0.20},
        {
            "name": "preceded_by_escalation",
            "weight": 0.20,
            "note": "Persistence following confirmed escalation = active breach"
        }
    ],
    "autonomous_response_threshold": 0.90,
    "analyst_review_threshold": 0.70
}

VERDICT_LOGIC = {
    "True Positive — Critical": {
        "conditions": [
            "systemd_persistence = CRITICAL (sources_triggered >= 2)",
            "OR (preceded_by_escalation = True AND any_persistence = True)"
        ],
        "confidence": "0.90+",
        "auto_response": "block_ip_opnsense + create_thehive_case + generate_pdf_report"
    },
    "True Positive — High": {
        "conditions": [
            "ssh_key_modification = HIGH",
            "OR cron_modification AND cron_execution fired"
        ],
        "confidence": "0.70-0.89",
        "auto_response": "create_thehive_case"
    }
}

FALSE_POSITIVE_RULES = [
    {
        "rule": "package_manager_cron",
        "description": "Package manager adding cron entries during installation",
        "conditions": "auid=system OR exe in (apt, dpkg)",
        "action": "suppress_alert"
    },
    {
        "rule": "legitimate_service_install",
        "description": "Software package creating systemd service",
        "conditions": "exe in (apt, dpkg, snap) AND systemctl_action in (enable, daemon-reload)",
        "action": "suppress_alert"
    }
]

HOST_HUNTING_CHECKLIST = [
    {
        "check": "SSH authorized keys",
        "command": "cat ~/.ssh/authorized_keys",
        "what_to_look_for": "Keys not belonging to known admins"
    },
    {
        "check": "Root crontab",
        "command": "sudo crontab -l",
        "what_to_look_for": "Entries with dev/tcp, nc, bash -i"
    },
    {
        "check": "Systemd services",
        "command": "sudo ls -la /etc/systemd/system/*.service",
        "what_to_look_for": "Real files not symlinks"
    },
    {
        "check": "Shell startup files",
        "command": "tail -5 ~/.bashrc",
        "what_to_look_for": "Reverse shell injection"
    }
]

RESPONSE_ACTIONS = {
    "immediate": [
        "Do NOT reboot — systemd persistence survives reboots",
        "Take Proxmox VM snapshot for forensic preservation"
    ],
    "eradication": [
        "Remove unauthorized SSH keys: sed -i '/kali@kali/d' ~/.ssh/authorized_keys",
        "Wipe malicious cron: sudo crontab -r",
        "Remove systemd backdoor: sudo systemctl stop SERVICE && sudo rm /etc/systemd/system/SERVICE.service",
        "Clean bashrc: sed -i '/dev\\/tcp/d' ~/.bashrc"
    ],
    "verification": [
        "SSH key test — should prompt for password now",
        "systemctl status removed_service — should show not found",
        "grep dev/tcp ~/.bashrc — should return nothing"
    ]
}

PLAYBOOK_CONNECTIONS = {
    "preceded_by": [
        {
            "playbook": "privilege_escalation.py",
            "reason": "Persistence almost always follows successful escalation",
            "confidence_modifier": "+0.20 if escalation confirmed in same session"
        }
    ],
    "escalates_to": [
        {
            "playbook": "network_recon.py",
            "trigger": "persistence confirmed AND outbound connections detected",
            "reason": "Persistent access used for ongoing exfiltration"
        }
    ]
}

BASELINE_METRICS = {
    "manual_detection": {
        "techniques_simulated": 4,
        "detection_rules_built": 5,
        "audit_rules_deployed": 30,
        "events_analyzed": 24883,
        "total_alert_fires": 82,
        "detection_rate": 1.0,
        "false_positive_rate": 0.0
    }
}

CYSA_CONNECTIONS = {
    "1.2": "Persistence — four MITRE techniques simulated and detected",
    "1.4": "Threat Hunting — four manual queries for persistence hunting",
    "2.3": "Validation of Remediation — all mechanisms removed and verified",
    "3.3": "Eradication Techniques — complete independent removal and verification"
}
