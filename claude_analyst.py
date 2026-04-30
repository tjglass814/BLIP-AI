"""
BLIP-AI Claude Analyst
======================
The reasoning layer. Takes structured Splunk findings
and produces a unified intelligent investigation report
covering the full Lockheed Martin Cyber Kill Chain.

Version: 1.1
Improvements:
- Attack timeline reconstruction
- Formalized CONFIRMED / SUSPECTED / NOT VERIFIED evidence tiers
- Severity and business impact assessment
- Detection coverage summary with ATT&CK gap analysis
- Automatic IOC extraction
- Confidence score transparency with weighted factors
"""

import os
import anthropic
from dotenv import load_dotenv

load_dotenv("config/.env")

class ClaudeAnalyst:

    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.model = "claude-sonnet-4-6"

    def analyze(self, findings):
        """
        Send investigation findings to Claude for unified analysis.
        Returns complete investigation report as a string.
        """
        prompt = self._build_prompt(findings)

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=10000,
                system="""You are BLIP-AI, an autonomous SOC analyst platform built on a Linux homelab.
You receive structured security investigation findings and produce a single unified investigation report.

Your report must follow this EXACT structure with ALL sections present:

---

# BLIP-AI UNIFIED INVESTIGATION REPORT

**Case ID:** [generate from alert type and timestamp]
**Triggering Alert:** [alert name]
**Primary Source IP:** [src_ip]
**Target:** [target host]
**Confidence Score:** [score]/1.0
**Incident Severity:** [CRITICAL / HIGH / MEDIUM / LOW]
**Report Generated:** [UTC timestamp]

---

## 1. EXECUTIVE SUMMARY
3 sentences maximum. What happened. Who did it. How bad is it right now.

---

## 2. INCIDENT SEVERITY AND BUSINESS IMPACT

**Severity Rating:** [CRITICAL / HIGH / MEDIUM / LOW]

**Severity Rationale:** Bullet points explaining the rating.

**Potential Business Impact:**
- Bullet list of what could happen if this is a real compromise

**Current Status:** [CONTAINED / ACTIVE / UNKNOWN]

---

## 3. ATTACK TIMELINE

Reconstruct the chronological sequence based on ALL available evidence.
Use the timestamps from the findings. Format as:

[EARLIEST TIMESTAMP] — [What happened] — [Source: which log/detection]
[NEXT TIMESTAMP]     — [What happened] — [Source: which log/detection]

If exact timestamps are not available for a stage, note it as ESTIMATED based on detection window.
End with current status.

---

## 4. EVIDENCE TIERS

Explicitly separate what is known from what is inferred.

**CONFIRMED** (direct evidence exists):
- Bullet list only — things with direct log evidence

**SUSPECTED** (logical inference from confirmed evidence):
- Bullet list only — things that are likely but not directly confirmed

**NOT VERIFIED** (possible but no evidence collected):
- Bullet list only — gaps in the evidence

---

## 5. CYBER KILL CHAIN ANALYSIS

Map evidence to all 7 Lockheed Martin kill chain phases.
For each phase state: CONFIRMED / SUSPECTED / NOT DETECTED
Include specific evidence for CONFIRMED stages only.
Do NOT claim CONFIRMED without direct evidence.

### Phase 1 — Reconnaissance
### Phase 2 — Weaponization
### Phase 3 — Delivery
### Phase 4 — Exploitation
### Phase 5 — Installation
### Phase 6 — Command & Control
### Phase 7 — Actions on Objectives

---

## 6. MITRE ATT&CK MAPPING

| Technique ID | Name | Status | Evidence |
|---|---|---|---|
[Only include techniques with at least SUSPECTED status]

---

## 7. DETECTION COVERAGE SUMMARY

Show which ATT&CK categories fired, which had gaps, and what BLIP-AI missed.

| ATT&CK Category | Detection Status | Alert Fired | Gap |
|---|---|---|---|
| Reconnaissance | ✅ / ⚠️ / ❌ | [alert name or none] | [gap if any] |
| Initial Access | ✅ / ⚠️ / ❌ | | |
| Execution | ✅ / ⚠️ / ❌ | | |
| Privilege Escalation | ✅ / ⚠️ / ❌ | | |
| Defense Evasion | ✅ / ⚠️ / ❌ | | |
| Credential Access | ✅ / ⚠️ / ❌ | | |
| Discovery | ✅ / ⚠️ / ❌ | | |
| Lateral Movement | ✅ / ⚠️ / ❌ | | |
| Collection | ✅ / ⚠️ / ❌ | | |
| Command & Control | ✅ / ⚠️ / ❌ | | |
| Exfiltration | ✅ / ⚠️ / ❌ | | |
| Persistence | ✅ / ⚠️ / ❌ | | |

---

## 8. CONFIDENCE SCORE BREAKDOWN

Show exactly why the score is what it is.

| Factor | Weight | Score Applied | Reason |
|---|---|---|---|
| [factor name] | +/- [weight] | [applied] | [reason] |

**Final Score: [X]/1.0**

Explain what would raise or lower this score with additional evidence.

---

## 9. INDICATORS OF COMPROMISE (IOCs)

**Source IPs:**
**Target IPs:**
**Ports Targeted:**
**Accounts Involved:**
**Tools Observed:**
**Files / Paths of Interest:**
**Signatures:** [any patterns that could be used in future detection rules]

---

## 10. PRIORITY ACTIONS

### 🔴 IMMEDIATE (0–15 minutes)
Numbered steps with bash commands. Stop active damage right now.

### 🟡 SHORT TERM (15–60 minutes)
Numbered steps with bash commands. Understand the full scope.

### 🟢 REMEDIATION (1–24 hours)
Numbered steps with bash commands. Prevent recurrence.

---

## 11. ANALYST NOTES

- What the automated system may have gotten wrong
- What inferences were made that are NOT confirmed
- What additional log sources would close the evidence gaps
- What a human analyst should verify manually before escalating

---

Be precise. Be accurate. Never state something as CONFIRMED without direct evidence.
Use bash code blocks for all commands.
This report may be used in a real incident response context.""",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            return message.content[0].text

        except Exception as e:
            return f"Claude analysis unavailable: {e}"

    def _build_prompt(self, findings):
        """Build comprehensive prompt with all evidence context."""

        checks = findings.get("checks", {})
        confidence = findings.get("confidence_score", 0)
        src_ip = findings.get("src_ip", "Unknown")
        alert_name = findings.get("alert_name", "Unknown")
        alert_type = findings.get("alert_type", "unknown")
        investigation_time = findings.get("investigation_time", "Unknown")

        # Build detailed evidence section
        evidence_lines = []

        recon = checks.get("reconnaissance", {})
        if recon.get("detected"):
            campaigns = recon.get("campaigns", [{}])
            c = campaigns[0]
            evidence_lines.append(
                f"NETWORK RECONNAISSANCE — CONFIRMED:\n"
                f"  Source IP: {c.get('src_ip', src_ip)}\n"
                f"  Scan windows: {c.get('scan_windows')} separate sessions detected\n"
                f"  Average unique ports per session: {c.get('avg_ports')}\n"
                f"  Campaign summary: {c.get('campaign_summary')}\n"
                f"  Target: OPNsense WAN interface (192.168.1.214) — perimeter scanning\n"
                f"  NOTE: Scan was directed at firewall WAN, not internal hosts directly\n"
                f"  MITRE: T1046 Network Service Discovery"
            )
        else:
            evidence_lines.append(
                "NETWORK RECONNAISSANCE — NOT DETECTED in current window\n"
                "  NOTE: Reconnaissance may have occurred outside the 4-hour detection window"
            )

        brute = checks.get("brute_force", {})
        if brute.get("detected"):
            evidence_lines.append(
                f"SSH BRUTE FORCE — CONFIRMED:\n"
                f"  Source IP: {brute.get('src_ip')}\n"
                f"  Failed authentication attempts: {brute.get('attempt_count')}\n"
                f"  Target service: SSH (TCP/22) on 10.10.10.198\n"
                f"  IMPORTANT: Failed attempts are confirmed. Successful login is NOT independently verified.\n"
                f"  Successful authentication requires separate confirmation from auth.log\n"
                f"  MITRE: T1110 Brute Force, T1021.004 Remote Services SSH"
            )
        else:
            evidence_lines.append(
                "SSH BRUTE FORCE — NOT DETECTED in current window"
            )

        escalation = checks.get("privilege_escalation", {})
        if escalation.get("detected"):
            procs = escalation.get("processes", [])
            proc_list = ', '.join(procs) if isinstance(procs, list) else str(procs)
            evidence_lines.append(
                f"PRIVILEGE ESCALATION — DETECTED (attribution unresolved):\n"
                f"  AUID (real user): {escalation.get('auid')}\n"
                f"  Effective UID: 0 (root) — confirmed at kernel level via auditd\n"
                f"  Processes executed with root privileges: {proc_list}\n"
                f"  CRITICAL CAVEAT: labadmin performs legitimate sudo activity regularly.\n"
                f"  This event CANNOT be attributed to the attacker without cross-referencing\n"
                f"  the exact timestamp of this event against SSH session logs.\n"
                f"  If no attacker SSH session was active at this time, this is legitimate admin activity.\n"
                f"  MITRE: T1548 Abuse Elevation Control Mechanism"
            )
        else:
            evidence_lines.append(
                "PRIVILEGE ESCALATION — NOT DETECTED in current window"
            )

        persistence = checks.get("persistence", {})
        if persistence.get("detected"):
            evidence_lines.append(
                f"PERSISTENCE — CONFIRMED:\n"
                f"  Mechanisms detected: {persistence.get('mechanisms')}\n"
                f"  Tools used: {persistence.get('tools')}\n"
                f"  MITRE: T1098.004 SSH Authorized Keys, T1053.003 Cron,\n"
                f"          T1543.002 Systemd Service, T1546.004 Bashrc Injection"
            )
        else:
            evidence_lines.append(
                "PERSISTENCE — NOT DETECTED in current window\n"
                "  NOTE: Absence of detection does not confirm absence of persistence.\n"
                "  Manual host verification recommended."
            )

        port_scan = checks.get("port_scan", {})
        if port_scan.get("detected"):
            evidence_lines.append(
                f"PORT SCAN ACTIVITY — CONFIRMED:\n"
                f"  Source IP: {port_scan.get('src_ip')}\n"
                f"  Unique destination ports: {port_scan.get('unique_ports')}\n"
                f"  Direction: FROM Kali (10.10.10.132) TO OPNsense WAN (192.168.1.214)\n"
                f"  IMPORTANT: This is external-to-perimeter scanning, NOT internal pivot scanning.\n"
                f"  The attacker was probing the firewall from the lab network, not scanning internal hosts.\n"
                f"  MITRE: T1046 Network Service Discovery"
            )
        else:
            evidence_lines.append(
                "PORT SCAN — NOT DETECTED in current window"
            )

        evidence_text = "\n\n".join(evidence_lines)

        # Build confidence factor breakdown
        confidence_factors = []
        if brute.get("detected"):
            confidence_factors.append(
                f"  +0.25 SSH brute force confirmed ({brute.get('attempt_count')} failed attempts)"
            )
        if escalation.get("detected"):
            confidence_factors.append(
                f"  +0.35 Privilege escalation detected (euid=0 from labadmin — attribution unresolved)"
            )
        if port_scan.get("detected"):
            confidence_factors.append(
                f"  +0.15 Port scan confirmed ({port_scan.get('unique_ports')} ports against OPNsense WAN)"
            )
        if recon.get("detected"):
            confidence_factors.append(
                f"  +0.20 Reconnaissance campaign confirmed (multiple scan windows)"
            )
        if not brute.get("detected"):
            confidence_factors.append(
                "  -0.10 No brute force detected (reduces attack chain confidence)"
            )
        if not persistence.get("detected"):
            confidence_factors.append(
                "  -0.05 No persistence detected (incomplete attack chain)"
            )
        confidence_factors.append(
            "  -0.10 Successful SSH login not independently verified"
        )
        confidence_factors.append(
            "  -0.10 Privilege escalation attribution unresolved"
        )

        confidence_breakdown = "\n".join(confidence_factors)

        prompt = f"""BLIP-AI INVESTIGATION REQUEST

Triggering Alert: {alert_name}
Alert Type Classified As: {alert_type}
Primary Source IP: {src_ip}
Investigation Timestamp: {investigation_time}
Automated Confidence Score: {confidence}/1.0

CONFIDENCE SCORING FACTORS:
{confidence_breakdown}

ENVIRONMENT CONTEXT:
- Target Server: Ubuntu 24.04 (splunk-server) at 10.10.10.198
- This server IS the Splunk SIEM — compromise would blind the entire SOC
- Attacker Platform: Kali Linux at 10.10.10.132
- Firewall: OPNsense at 10.10.10.1 (LAN) / 192.168.1.214 (WAN)
- Lab Network: Isolated 10.10.10.x segment
- Lab Owner Account: labadmin (UID 1000) — performs regular legitimate sudo activity
- Detection Sources: auditd (host), linux_secure (auth), OPNsense filterlog (network)
- Detection Window: Last 4 hours

STRUCTURED EVIDENCE:

{evidence_text}

ANALYST GUIDANCE:
- Only mark a kill chain phase CONFIRMED if direct evidence exists above
- labadmin's sudo activity is routine — do not assume it is attacker activity
- Port scan was against firewall WAN, not internal hosts
- Brute force failures are confirmed — success is NOT confirmed
- The confidence score factors are provided above — use them in section 8
- Timestamps in the evidence are approximate — use investigation timestamp as reference
- This is a security homelab — frame findings appropriately

Produce the complete unified investigation report now following the exact structure specified."""

        return prompt

    def test_connection(self):
        """Quick test to verify Claude API is working."""
        try:
            msg = self.client.messages.create(
                model=self.model,
                max_tokens=30,
                messages=[{
                    "role": "user",
                    "content": "Respond with exactly: BLIP-AI Claude analyst online."
                }]
            )
            return True, msg.content[0].text
        except Exception as e:
            return False, str(e)


if __name__ == "__main__":
    analyst = ClaudeAnalyst()
    print("Testing Claude analyst connection...")
    success, response = analyst.test_connection()
    if success:
        print(f"✅ {response}")
        print("\nClaude API is working — BLIP-AI reasoning layer ready.")
    else:
        print(f"❌ Connection failed: {response}")
