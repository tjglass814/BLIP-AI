"""
BLIP-AI Playbook: Defense Evasion and Anti-Forensics Detection
==============================================================
Based on manual detection project:
Taylor-Cybersecurity-Homelab/Projects/Domain-01-Linux-SIEM/06-Defense-Evasion-Anti-Forensics

MITRE ATT&CK:
- T1070.001  Indicator Removal: Clear Windows Event Logs
- T1070.002  Indicator Removal: Clear Linux or Mac System Logs
- T1070.003  Indicator Removal: Clear Command History
- T1070.006  Indicator Removal: Timestomp
- T1485      Data Destruction
- T1562.001  Impair Defenses: Disable or Modify Tools

Version: 1.0
Author: BLIP-AI / Taylor Glass

Key Architectural Concepts:
- Telemetry survivability scoring — measures how blind the attacker made us
- Race condition awareness — auditd logs its own death before shutdown
- Session-scoped correlation — ties techniques to specific SSH sessions
- Escalation-to-evasion temporal correlation — the crown jewel detection

V2 Improvements (Eva feedback — locked in):
- Move from tool-name detection to syscall behavior (unlink/write/truncate patterns)
- Add temporal sequence logic (did anti-forensics occur AFTER escalation?)
- Add host criticality multiplier (SIEM host scores higher than workstation)
- Capture and analyze command arguments (auditctl -e 0 vs auditctl -s)
- Behavior-state transitions (telemetry healthy → degraded)
"""

PLAYBOOK = {
    "name": "Defense Evasion and Anti-Forensics Detection",
    "version": "1.0",
    "mitre_techniques": [
        "T1070.001", "T1070.002", "T1070.003", "T1070.006",
        "T1485", "T1562.001"
    ],
    "trigger_conditions": [
        "auditd or auditctl execution by interactive user",
        "Critical log file deleted or truncated",
        "Shell history file deleted or symlinked to /dev/null",
        "Explicit timestamp modification via touch -t or touch -d",
        "Secure deletion tool executed — shred, wipe, srm",
        "Multiple evasion techniques from same session within 1 hour",
        "Anti-forensics detected within 60 minutes of privilege escalation",
        "Splunk Universal Forwarder stopped and restarted"
    ],
    "required_sources": ["linux_audit"],
    "confidence_threshold": 0.75,
    "auto_response_threshold": 0.90,
    "telemetry_survivability": True
}

TELEMETRY_SURVIVABILITY = {
    "description": "Measures how much detection capability the attacker destroyed",
    "events": {
        "auditd_stopped": {
            "impact": "SEVERE",
            "description": "All kernel telemetry lost until restart",
            "platform_flag": "telemetry_integrity=DEGRADED"
        },
        "splunk_forwarder_stopped": {
            "impact": "SEVERE",
            "description": "SIEM receives nothing — auditd writes to disk only",
            "platform_flag": "siem_pipeline=SEVERED"
        },
        "log_file_deleted": {
            "impact": "MODERATE",
            "description": "Historical evidence partially destroyed",
            "platform_flag": "log_integrity=COMPROMISED"
        },
        "history_cleared": {
            "impact": "LOW",
            "description": "Command trail evidence destroyed",
            "platform_flag": "command_trail=DESTROYED"
        }
    }
}

INVESTIGATION_STEPS = [
    {
        "step": 1,
        "name": "Audit System Tampering Detection",
        "description": "Detects interactive and non-interactive modification or "
                       "disabling of the auditd kernel monitoring system. "
                       "Uses TTY context scoring not hard filtering — "
                       "interactive tampering scores CRITICAL, "
                       "non-interactive scores MEDIUM. Both surface. "
                       "Captures auditctl -e 0 via argument analysis. "
                       "Sets telemetry_integrity=DEGRADED platform-wide.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-15m
            (key="audit_tampering" OR key="audit_rules_modified")
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "ses=(?P<ses>\\d+)"
            | rex field=_raw "tty=(?P<tty>\\S+)"
            | rex field=_raw "a0=\\"(?P<a0>[^\\"]+)\\""
            | rex field=_raw "a1=\\"(?P<a1>[^\\"]+)\\""
            | where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
            | where success="yes" OR success="1"
            | eval interaction_type=if(tty="(none)","non_interactive","interactive")
            | eval binary=mvindex(split(exe,"/"),-1)
            | eval args=coalesce(a0,"")." ".coalesce(a1,"")
            | eval dangerous_args=if(
                match(args,"-e 0|-e0|-D|-d"),
                "YES — Audit rules disabled or deleted",
                "NO — Standard audit operation")
            | eval technique=case(
                binary="auditctl" AND dangerous_args="YES — Audit rules disabled or deleted",
                    "Audit rules explicitly disabled — T1562.001",
                binary="auditctl", "Audit configuration modified",
                binary="systemctl" AND match(args,"stop|disable|mask"),
                    "Audit service stopped via systemctl — T1562.001",
                true(), "Unknown audit system tampering")
            | eval telemetry_integrity=if(
                match(technique,"disabled|stopped"),
                "DEGRADED — Kernel telemetry at risk",
                "MONITOR — Audit configuration changed")
            | eval base_score=case(
                interaction_type="interactive"
                    AND dangerous_args="YES — Audit rules disabled or deleted", 0.95,
                interaction_type="interactive", 0.80,
                interaction_type="non_interactive"
                    AND dangerous_args="YES — Audit rules disabled or deleted", 0.85,
                interaction_type="non_interactive", 0.60,
                true(), 0.50)
            | stats count values(exe) as tools values(technique) as techniques
                values(interaction_type) as session_type
                values(dangerous_args) as argument_analysis
                values(telemetry_integrity) as telemetry_status
                max(base_score) as confidence_score by auid host
            | eval risk_level=case(
                confidence_score>=0.90, "CRITICAL — Audit system disabled by interactive user",
                confidence_score>=0.80, "HIGH — Interactive audit tampering detected",
                confidence_score>=0.60, "MEDIUM — Non-interactive audit modification",
                true(), "LOW — Audit system activity")
            | table auid host count tools techniques session_type
                argument_analysis telemetry_status confidence_score risk_level
            | sort -confidence_score
        """,
        "confidence_weight": 0.35,
        "mitre": "T1562.001",
        "race_condition_note": "auditd logs its own death before shutdown — "
                               "final record captured if forwarder ships in time"
    },
    {
        "step": 2,
        "name": "Log File Deletion or Destruction",
        "description": "Detects deletion, truncation, or secure wiping of critical "
                       "log files. PATH record join identifies specific file targeted. "
                       "File criticality scoring: auth.log/audit.log=CRITICAL, "
                       "syslog/kern.log=HIGH. "
                       "Deletion method scoring: shred=0.98, rm=0.85, truncate=0.85.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-15m
            (key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper")
            | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | rex field=_raw "tty=(?P<tty>\\S+)"
            | where auid!="unset" AND auid!="4294967295"
            | where success="yes" OR success="1"
            | join event_id [
                search index=main sourcetype=linux_audit type=PATH
                | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
                | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
                | rex field=_raw "nametype=(?P<nametype>\\w+)"
                | where match(filepath,"/var/log")
                | table event_id filepath nametype
            ]
            | eval interaction_type=if(tty="(none)","non_interactive","interactive")
            | eval binary=mvindex(split(exe,"/"),-1)
            | eval file_criticality=case(
                match(filepath,"auth\\.log|secure|audit\\.log"),
                    "CRITICAL FILE — Authentication or audit evidence",
                match(filepath,"syslog|messages|kern\\.log"),
                    "HIGH FILE — System operational evidence",
                true(), "MODERATE FILE — General log evidence")
            | eval deletion_method=case(
                binary="shred", "Secure overwrite — forensic recovery prevented",
                binary="rm", "Standard deletion — forensic recovery possible",
                binary="truncate", "File zeroed — content destroyed",
                true(), "Unknown modification method")
            | eval base_score=case(
                binary="shred" AND match(filepath,"auth\\.log|secure|audit\\.log"), 0.98,
                binary="shred", 0.95,
                binary="rm" AND match(filepath,"auth\\.log|secure|audit\\.log")
                    AND interaction_type="interactive", 0.90,
                binary="rm" AND interaction_type="interactive", 0.85,
                binary="truncate" AND interaction_type="interactive", 0.85,
                true(), 0.50)
            | stats count values(exe) as tools values(deletion_method) as methods
                values(filepath) as files_targeted values(file_criticality) as criticality
                values(interaction_type) as session_type
                max(base_score) as confidence_score by auid host
            | eval risk_level=case(
                confidence_score>=0.95, "CRITICAL — Forensic-grade destruction",
                confidence_score>=0.85, "HIGH — Critical log file deleted",
                true(), "MEDIUM — Log file activity")
            | table auid host count tools methods files_targeted criticality
                session_type confidence_score risk_level
            | sort -confidence_score
        """,
        "confidence_weight": 0.25,
        "mitre": "T1070.002",
        "inode_note": "Deleted files destroy auditd inode watch — "
                      "auditd restart re-establishes watches on new inodes"
    },
    {
        "step": 3,
        "name": "Shell History Evasion",
        "description": "Detects deletion, symlinking, or modification of shell "
                       "history files. PATH record join identifies specific file. "
                       "Multi-shell: bash, zsh, python history. "
                       "Symlink to /dev/null scores highest at 0.90 — "
                       "most sophisticated technique. "
                       "V2 will add escalation temporal correlation.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-15m
            key="history_tamper"
            | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | rex field=_raw "tty=(?P<tty>\\S+)"
            | where auid!="unset" AND auid!="4294967295"
            | where success="yes" OR success="1"
            | join event_id [
                search index=main sourcetype=linux_audit type=PATH
                | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
                | rex field=_raw "name=\\"(?P<filepath>[^\\"]+)\\""
                | rex field=_raw "nametype=(?P<nametype>\\w+)"
                | where match(filepath,"bash_history|zsh_history|python_history")
                | table event_id filepath nametype
            ]
            | eval interaction_type=if(tty="(none)","non_interactive","interactive")
            | eval binary=mvindex(split(exe,"/"),-1)
            | eval evasion_technique=case(
                binary="ln", "History symlinked to /dev/null — future commands hidden",
                binary="rm" AND nametype="DELETE",
                    "History file deleted — command trail destroyed",
                binary="truncate", "History file zeroed — content destroyed",
                binary="bash" OR binary="sh",
                    "Shell writing to history file — possible overwrite",
                true(), "Unknown history modification")
            | eval base_score=case(
                binary="ln" AND interaction_type="interactive", 0.90,
                binary="rm" AND interaction_type="interactive", 0.85,
                binary="truncate" AND interaction_type="interactive", 0.80,
                true(), 0.50)
            | stats count values(exe) as tools
                values(evasion_technique) as techniques
                values(filepath) as history_files
                values(interaction_type) as session_type
                max(base_score) as confidence_score by auid host
            | eval risk_level=case(
                confidence_score>=0.88, "CRITICAL — Multiple history evasion techniques",
                confidence_score>=0.80, "HIGH — Shell history destroyed",
                true(), "MEDIUM — History file modification")
            | eval v2_note="Escalation correlation pending — V2 raises severity when same session shows prior euid=0"
            | table auid host count tools techniques history_files
                session_type confidence_score risk_level v2_note
            | sort -confidence_score
        """,
        "confidence_weight": 0.20,
        "mitre": "T1070.003",
        "known_gaps": [
            "history -c — bash built-in, no syscall generated",
            "unset HISTFILE — environment variable, invisible to auditd",
            "export HISTSIZE=0 — environment variable, invisible to auditd",
            "HISTCONTROL=ignorespace — prevents recording without touching files"
        ]
    },
    {
        "step": 4,
        "name": "Timestamp Manipulation Detection",
        "description": "Detects explicit timestamp modification via touch -t or -d "
                       "flags using PROCTITLE hex decoding. "
                       "Detects timestomping behavior not binary name — "
                       "renamed touch binary still passes -t flag. "
                       "Extracts execution tool for sophistication scoring. "
                       "Birth time (crtime) survives all touch manipulation.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-15m
            type=PROCTITLE
            | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
            | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
            | eval proctitle_clean=replace(proctitle_hex,"00"," ")
            | eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\\1"))
            | where match(decoded,"(^|\\s)(-t|-d|--date)(\\s|$)")
            | join event_id [
                search index=main sourcetype=linux_audit type=SYSCALL
                | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
                | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
                | rex field=_raw "ses=(?P<ses>\\d+)"
                | rex field=_raw "tty=(?P<tty>\\S+)"
                | rex field=_raw "success=(?P<success>\\w+)"
                | where auid!="unset" AND auid!="4294967295"
                | where success="yes" OR success="1"
                | table event_id auid ses tty success
            ]
            | eval interaction_type=if(tty="(none)","non_interactive","interactive")
            | eval execution_tool=mvindex(split(trim(decoded)," "),0)
            | eval filepath=mvindex(split(trim(decoded)," "),-1)
            | eval tool_sophistication=case(
                match(execution_tool,"debugfs|perl|python|ruby"),
                    "HIGH — Advanced timestomping tool",
                match(execution_tool,"touch|sudo"),
                    "MEDIUM — Standard timestomping tool",
                true(), "LOW — Unknown tool")
            | eval base_score=case(
                match(filepath,"/tmp/|/dev/shm/")
                    AND interaction_type="interactive", 0.85,
                match(filepath,"\\.sh$|\\.py$|\\.pl$|\\.elf$"), 0.85,
                interaction_type="interactive", 0.75,
                true(), 0.60)
            | stats count values(decoded) as full_command
                values(execution_tool) as tools_used
                values(tool_sophistication) as tool_assessment
                values(filepath) as files_targeted
                values(interaction_type) as session_type
                max(base_score) as confidence_score by auid host
            | eval risk_level=case(
                confidence_score>=0.85, "HIGH — Timestomping detected",
                true(), "MEDIUM — Timestamp manipulation")
            | eval forensic_note="Birth time (crtime) cannot be modified with touch — preserved as forensic anchor"
            | eval known_gaps="debugfs and binary renaming bypass this detection"
            | table auid host count full_command tools_used tool_assessment
                files_targeted session_type confidence_score risk_level
                forensic_note known_gaps
            | sort -confidence_score
        """,
        "confidence_weight": 0.15,
        "mitre": "T1070.006",
        "forensic_note": "Birth time (crtime) cannot be modified with touch — "
                         "preserved as forensic anchor even after successful timestomping",
        "known_gaps": [
            "debugfs can modify timestamps at filesystem level — bypasses detection",
            "Binary renaming bypasses tool name matching — behavior detection via flag is more robust",
            "PROCTITLE hex decoding is fragile — special characters may break extraction"
        ]
    },
    {
        "step": 5,
        "name": "Secure Deletion Tool Execution",
        "description": "Detects forensic-grade secure deletion tools — shred, wipe, srm. "
                       "Uses PROCTITLE decoding to identify target files. "
                       "Tool severity: shred/wipe/srm=CRITICAL. "
                       "Target scoring: /var/log/ deletion scores 0.98. "
                       "Recovery status: data overwritten multiple times — "
                       "forensic recovery significantly impaired.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-15m
            type=PROCTITLE
            | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
            | rex field=_raw "proctitle=(?P<proctitle_hex>[A-Fa-f0-9]+)"
            | eval proctitle_clean=replace(proctitle_hex,"00"," ")
            | eval decoded=urldecode(replace(proctitle_clean,"([A-Fa-f0-9]{2})","%" . "\\1"))
            | where match(decoded,"(^|\\s)(shred|wipe|srm)(\\s|$)")
            | join event_id [
                search index=main sourcetype=linux_audit type=SYSCALL
                | rex field=_raw "msg=audit\\([^:]+:(?P<event_id>\\d+)\\)"
                | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
                | rex field=_raw "ses=(?P<ses>\\d+)"
                | rex field=_raw "tty=(?P<tty>\\S+)"
                | rex field=_raw "success=(?P<success>\\w+)"
                | where auid!="unset" AND auid!="4294967295"
                | where success="yes" OR success="1"
                | table event_id auid ses tty success
            ]
            | eval interaction_type=if(tty="(none)","non_interactive","interactive")
            | eval execution_tool=mvindex(split(trim(decoded)," "),0)
            | eval filepath=mvindex(split(trim(decoded)," "),-1)
            | eval base_score=case(
                match(execution_tool,"shred|wipe|srm")
                    AND match(filepath,"/var/log/")
                    AND interaction_type="interactive", 0.98,
                match(execution_tool,"shred|wipe|srm")
                    AND interaction_type="interactive", 0.92,
                match(execution_tool,"shred|wipe|srm"), 0.80,
                true(), 0.65)
            | stats count values(decoded) as full_command
                values(execution_tool) as tools_used
                values(filepath) as files_targeted
                values(interaction_type) as session_type
                max(base_score) as confidence_score by auid host
            | eval risk_level=case(
                confidence_score>=0.95, "CRITICAL — Forensic evidence permanently destroyed",
                confidence_score>=0.85, "CRITICAL — Secure deletion by interactive user",
                true(), "HIGH — Secure deletion tool detected")
            | eval recovery_status="SEVERE — Data overwritten multiple times — forensic recovery significantly impaired"
            | table auid host count full_command tools_used files_targeted
                session_type confidence_score risk_level recovery_status
            | sort -confidence_score
        """,
        "confidence_weight": 0.25,
        "mitre": "T1485"
    },
    {
        "step": 6,
        "name": "Combined Anti-Forensics Behavioral Score",
        "description": "Correlates multiple evasion techniques from same session "
                       "within 1 hour. Session-scoped via ses field prevents "
                       "false correlation across separate admin sessions. "
                       "Two techniques = HIGH. Three or more = CRITICAL. "
                       "Telemetry integrity flag surfaces when auditd interrupted. "
                       "This is the multi-signal behavioral detection.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-1h
            (key="audit_tampering" OR key="audit_rules_modified"
            OR key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper"
            OR key="history_tamper" OR key="timestamp_tamper" OR key="secure_delete"
            OR key="journald_tamper")
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "ses=(?P<ses>\\d+)"
            | rex field=_raw "tty=(?P<tty>\\S+)"
            | rex field=_raw "success=(?P<success>\\w+)"
            | rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
            | where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
            | where success="yes" OR success="1"
            | eval interaction_type=if(tty="(none)","non_interactive","interactive")
            | eval technique=case(
                key="audit_tampering" OR key="audit_rules_modified",
                    "Audit System Tampered",
                key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper",
                    "Log File Destroyed",
                key="history_tamper", "Shell History Erased",
                key="timestamp_tamper", "Timestamps Manipulated",
                key="secure_delete", "Secure Deletion Tool Used",
                key="journald_tamper", "Journal Tampered",
                true(), "Unknown Evasion")
            | eval technique_weight=case(
                key="audit_tampering" OR key="audit_rules_modified", 0.35,
                key="auth_log_tamper" OR key="syslog_tamper" OR key="log_tamper", 0.25,
                key="history_tamper", 0.20,
                key="secure_delete", 0.25,
                key="timestamp_tamper", 0.15,
                key="journald_tamper", 0.20,
                true(), 0.10)
            | stats
                dc(technique) as technique_count
                values(technique) as techniques_detected
                sum(technique_weight) as raw_score
                values(interaction_type) as session_types
                min(_time) as first_seen
                max(_time) as last_seen
                by auid host ses
            | eval evasion_duration_minutes=round((last_seen - first_seen)/60, 1)
            | eval combined_score=min(round(raw_score, 2), 1.0)
            | eval interactive_bonus=if(
                mvfind(session_types,"interactive")>=0, 0.10, 0.0)
            | eval final_confidence=min(combined_score + interactive_bonus, 1.0)
            | where technique_count >= 2
            | eval risk_level=case(
                technique_count>=4, "CRITICAL — Systematic anti-forensics campaign",
                technique_count>=3, "CRITICAL — Multiple evasion techniques in same session",
                technique_count>=2, "HIGH — Combined evasion behavior detected",
                true(), "MEDIUM — Evasion activity")
            | eval attack_phase="POST-EXPLOITATION CLEANUP — Attacker actively destroying evidence"
            | eval telemetry_integrity=case(
                mvfind(techniques_detected,"Audit System Tampered")>=0,
                    "DEGRADED — Kernel telemetry was interrupted during attack window",
                true(), "INTACT — Full telemetry coverage maintained")
            | table auid host ses technique_count techniques_detected
                final_confidence risk_level evasion_duration_minutes
                attack_phase telemetry_integrity
            | sort -final_confidence
        """,
        "confidence_weight": 0.40,
        "mitre": "T1070, T1562"
    },
    {
        "step": 7,
        "name": "Escalation-to-Evasion Temporal Correlation",
        "description": "THE crown jewel detection. Proves sequence not just co-occurrence. "
                       "Anti-forensics AFTER escalation from same session = probable attacker. "
                       "Confidence decays with time — under 5 minutes = 0.95 CRITICAL. "
                       "Evasion bonus for multiple techniques. "
                       "evasion_time > escalation_time is the sequence enforcement line.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-2h
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "ses=(?P<ses>\\d+)"
            | rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
            | rex field=_raw "(?i)euid[=:\\"](?P<euid>\\d+)"
            | rex field=_raw "success=(?P<success>\\w+)"
            | where auid!="unset" AND auid!="4294967295" AND isnotnull(auid)
            | where success="yes" OR success="1"
            | eval event_category=case(
                match(key,"audit_tampering|audit_rules_modified"), "anti_forensics",
                match(key,"auth_log_tamper|syslog_tamper|log_tamper"), "anti_forensics",
                match(key,"history_tamper"), "anti_forensics",
                match(key,"timestamp_tamper"), "anti_forensics",
                match(key,"secure_delete"), "anti_forensics",
                euid="0" AND auid!="0" AND isnotnull(euid), "escalation",
                true(), null())
            | where isnotnull(event_category)
            | stats
                min(eval(if(event_category="escalation",_time,null()))) as escalation_time
                min(eval(if(event_category="anti_forensics",_time,null()))) as evasion_time
                values(eval(if(event_category="anti_forensics",key,null()))) as evasion_keys
                dc(eval(if(event_category="anti_forensics",key,null()))) as evasion_technique_count
                by auid ses host
            | where isnotnull(escalation_time) AND isnotnull(evasion_time)
            | where evasion_time > escalation_time
            | eval minutes_between=round((evasion_time - escalation_time)/60, 1)
            | where minutes_between <= 60
            | eval sequence_confidence=case(
                minutes_between <= 5,  0.95,
                minutes_between <= 15, 0.90,
                minutes_between <= 30, 0.85,
                minutes_between <= 60, 0.75,
                true(), 0.60)
            | eval evasion_bonus=case(
                evasion_technique_count >= 3, 0.10,
                evasion_technique_count >= 2, 0.05,
                true(), 0.0)
            | eval final_confidence=min(sequence_confidence + evasion_bonus, 1.0)
            | eval risk_level=case(
                final_confidence >= 0.95, "CRITICAL — Immediate cleanup after escalation",
                final_confidence >= 0.85, "CRITICAL — Anti-forensics followed escalation",
                final_confidence >= 0.75, "HIGH — Probable attacker cleanup sequence",
                true(), "MEDIUM — Suspicious escalation-evasion proximity")
            | eval attack_narrative=
                "Privilege escalation at ".strftime(escalation_time,"%H:%M:%S").
                " → Anti-forensics at ".strftime(evasion_time,"%H:%M:%S").
                " (".tostring(minutes_between)." minutes later)"
            | eval techniques_used=mvjoin(evasion_keys," | ")
            | table auid host ses attack_narrative techniques_used
                evasion_technique_count minutes_between
                final_confidence risk_level
            | sort -final_confidence
        """,
        "confidence_weight": 0.45,
        "mitre": "T1562, T1070, T1548",
        "architectural_note": "This detection transforms suspicious activity into "
                              "probable attacker behavior by enforcing sequence. "
                              "evasion_time > escalation_time is the critical enforcement line."
    },
    {
        "step": 8,
        "name": "Splunk Forwarder Stopped",
        "description": "Detects stop/start cycle of Splunk Universal Forwarder. "
                       "Gap between invocations = SIEM blind window. "
                       "auditd continues writing to disk during gap — "
                       "attacker has unmonitored window in Splunk. "
                       "Different from auditd tampering — targets pipeline not collection.",
        "phase": "defense_evasion",
        "splunk_query": """
            index=main sourcetype=linux_audit earliest=-15m
            key="forwarder_tamper"
            type=SYSCALL
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "ses=(?P<ses>\\d+)"
            | rex field=_raw "tty=(?P<tty>\\S+)"
            | rex field=_raw "success=(?P<success>\\w+)"
            | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
            | where auid!="unset" AND auid!="4294967295"
            | where success="yes" OR success="1"
            | where comm="splunk"
            | sort _time
            | streamstats count as n first(_time) as t1 last(_time) as t2 by auid ses
            | where n>=2
            | eval gap=round(t2-t1,0)
            | eval score=if(gap>120,0.90,if(gap>30,0.85,0.75))
            | dedup auid ses
            | table auid ses gap score
        """,
        "confidence_weight": 0.30,
        "mitre": "T1562",
        "known_limitation": "Cannot distinguish stop vs start from SYSCALL alone — "
                            "EXECVE/PROCTITLE records not shipping for this binary. "
                            "Gap calculation provides behavioral signal regardless."
    }
]

ARCHITECTURAL_LIMITATIONS = {
    "bash_builtins": {
        "description": "Shell built-ins generate no syscalls — invisible to auditd",
        "affected_techniques": [
            "history -c — clears in-memory history",
            "unset HISTFILE — disables history file",
            "export HISTSIZE=0 — sets history size to zero",
            "HISTCONTROL=ignorespace — prevents space-prefixed commands"
        ],
        "detection_approach": "Behavioral inference — if no history file write occurs "
                              "despite active shell, that absence is suspicious. V2 improvement."
    },
    "auditd_race_condition": {
        "description": "auditd logs its own death before shutdown — "
                       "final record captured if forwarder ships in time. "
                       "Stop event may not reach Splunk if shutdown is rapid.",
        "mitigation": "Real-time log forwarding minimizes the gap. "
                      "journald captures the stop event independently."
    },
    "inode_watching": {
        "description": "auditd watches inodes not paths. "
                       "Deleting a watched file destroys the watch. "
                       "New file with same name gets new inode — watch lost.",
        "mitigation": "auditd restart re-establishes watches on current inodes. "
                      "Catch deletion before inode is destroyed."
    },
    "shell_redirect_truncation": {
        "description": "> /var/log/auth.log uses shell built-in redirect operator — "
                       "no binary executed, no EXECVE record generated.",
        "mitigation": "Filesystem PATH records catch the write operation. "
                      "auditd -p wa on the file catches the write syscall."
    },
    "proctitle_fragility": {
        "description": "PROCTITLE hex decoding can break with special characters "
                       "or non-standard encoding.",
        "mitigation": "EXECVE records as fallback when PROCTITLE unavailable."
    }
}

RISK_SCORING = {
    "base_score": 0.0,
    "confidence_factors": [
        {"name": "audit_system_tampered", "weight": 0.35,
         "note": "Highest single weight — disabling detection is strongest malicious signal"},
        {"name": "log_file_destroyed", "weight": 0.25},
        {"name": "secure_deletion_used", "weight": 0.25,
         "note": "shred/wipe against /var/log scores 0.98"},
        {"name": "history_erased", "weight": 0.20},
        {"name": "timestamp_manipulated", "weight": 0.15},
        {"name": "multiple_techniques_same_session", "weight": 0.40,
         "note": "Combined behavioral score — most powerful signal"},
        {"name": "escalation_preceded_evasion", "weight": 0.45,
         "note": "Crown jewel — sequence proof transforms suspicious to probable attacker"}
    ],
    "autonomous_response_threshold": 0.90,
    "analyst_review_threshold": 0.70
}

VERDICT_LOGIC = {
    "True Positive — Critical": {
        "conditions": [
            "escalation_to_evasion confirmed in same session under 5 minutes",
            "OR audit system disabled AND log files destroyed in same session",
            "OR combined score >= 3 techniques in same session"
        ],
        "confidence": "0.90+",
        "auto_response": "block_ip_opnsense + create_thehive_case + generate_pdf_report"
    },
    "True Positive — High": {
        "conditions": [
            "Two or more techniques in same session",
            "OR single critical technique — shred against /var/log"
        ],
        "confidence": "0.70-0.89",
        "auto_response": "create_thehive_case"
    },
    "False Positive": {
        "conditions": [
            "Confirmed labadmin maintenance window",
            "OR package manager activity touching audit config",
            "OR logrotate touching monitored log files"
        ],
        "confidence": "<0.30",
        "auto_response": "suppress_alert"
    }
}

FALSE_POSITIVE_CONDITIONS = [
    "logrotate — legitimate log rotation",
    "apt/dpkg — package manager touching audit config",
    "rsyslog — syslog daemon internal writes",
    "anacron — scheduled maintenance",
    "systemd — service management during package install"
]

HOST_VERIFICATION_CHECKLIST = [
    {
        "check": "Confirm auditd rules intact",
        "command": "sudo auditctl -l | wc -l",
        "what_to_look_for": "Rule count matches baseline (45)"
    },
    {
        "check": "Verify log files exist",
        "command": "ls -la /var/log/auth.log /var/log/syslog /var/log/kern.log",
        "what_to_look_for": "Files present with recent timestamps"
    },
    {
        "check": "Check bash history",
        "command": "ls -la ~/.bash_history && cat ~/.bash_history | tail -20",
        "what_to_look_for": "File exists and not symlinked to /dev/null"
    },
    {
        "check": "Verify Splunk forwarder running",
        "command": "sudo /opt/splunkforwarder/bin/splunk status",
        "what_to_look_for": "splunkd is running"
    },
    {
        "check": "Check for recent file timestamp anomalies",
        "command": "find /tmp /var/tmp -newer /var/log/auth.log -ls 2>/dev/null",
        "what_to_look_for": "Files with suspiciously old modify times but recent birth times"
    }
]

RESPONSE_ACTIONS = {
    "immediate": [
        "Verify auditd is still running: sudo systemctl status auditd",
        "Confirm rule count: sudo auditctl -l | wc -l",
        "Check active sessions: who && w && last | head -20",
        "Verify Splunk forwarder running: sudo /opt/splunkforwarder/bin/splunk status"
    ],
    "investigation": [
        "Pull full session audit trail: sudo ausearch -ua labadmin -ts today",
        "Cross-reference escalation timestamp against SSH session logs",
        "Check /root/.bash_history for commands run during evasion window",
        "Review OPNsense filterlog for unusual outbound connections"
    ],
    "remediation": [
        "Restart auditd to re-establish inode watches: sudo systemctl restart auditd",
        "Restore deleted logs from Splunk index if needed",
        "Rotate credentials if attacker session confirmed",
        "Document telemetry gap duration in incident timeline"
    ]
}

PLAYBOOK_CONNECTIONS = {
    "preceded_by": [
        {
            "playbook": "privilege_escalation.py",
            "reason": "Anti-forensics almost always follows successful escalation",
            "confidence_modifier": "+0.45 if escalation-to-evasion sequence confirmed"
        }
    ],
    "blip_ai_confidence_contribution": {
        "standalone_anti_forensics": 0.25,
        "multi_technique_session": 0.40,
        "escalation_to_evasion_confirmed": 0.45,
        "note": "Anti-forensics is the strongest post-escalation signal in the platform"
    }
}

BASELINE_METRICS = {
    "manual_detection": {
        "auditd_rules_added": 15,
        "total_auditd_rules": 45,
        "splunk_detections_built": 8,
        "attack_simulations_run": 9,
        "attacks_detected": 8,
        "detection_rate": 0.89,
        "architectural_limitations_documented": 4,
        "known_gaps": 3,
        "highest_confidence_detection": 1.0,
        "detection_names": [
            "Audit System Tampered",
            "Log File Deletion or Destruction",
            "Shell History Evasion",
            "Timestamp Manipulation",
            "Secure Deletion Tools Executed",
            "Combined Anti-Forensics Behavioral Score",
            "Escalation-to-Evasion Temporal Correlation",
            "Splunk Forwarder Stopped"
        ]
    }
}

CYSA_CONNECTIONS = {
    "1.1": "Log Configuration — targeted auditd rules vs broad watches",
    "1.2": "Defense Evasion — T1562.001 impair defenses, T1070 indicator removal",
    "1.3": "SIEM SPL — 8 behavioral detections with confidence scoring",
    "1.4": "Behavioral Analytics — multi-signal correlation, session-scoped",
    "1.5": "Alert Tuning — TTY context scoring reduces false positives",
    "2.1": "File Integrity Monitoring — inode-based watching limitations",
    "2.3": "Detection Validation — all detections confirmed with real attack data",
    "3.2": "Detection Phase — race condition awareness, telemetry survivability",
    "3.3": "Evidence Preservation — birth time forensic anchor, rsyslog recreation"
}

V2_IMPROVEMENTS = {
    "source": "Eva senior SOC analyst review",
    "improvements": [
        {
            "title": "Syscall behavior detection",
            "description": "Move from tool-name matching to syscall patterns — "
                           "unlink/write/truncate syscalls not binary names. "
                           "Renamed binaries bypass current detections."
        },
        {
            "title": "Temporal sequence logic",
            "description": "Enforce ordering — did anti-forensics occur AFTER escalation? "
                           "Did secure deletion occur AFTER payload execution? "
                           "Did audit tampering occur BEFORE telemetry loss?"
        },
        {
            "title": "Host criticality multiplier",
            "description": "SIEM anti-forensics should score higher than workstation. "
                           "SIEM=CRITICAL, DC=CRITICAL, workstation=HIGH."
        },
        {
            "title": "Command argument intelligence",
            "description": "auditctl -e 0 vs auditctl -s are completely different. "
                           "Argument capture requires EXECVE join — "
                           "currently fragile due to record shipping gaps."
        },
        {
            "title": "Behavior-state transitions",
            "description": "Model state changes not just events: "
                           "telemetry healthy → degraded, "
                           "logs present → deleted, "
                           "history active → disabled. "
                           "True adversary behavior modeling."
        }
    ]
}
