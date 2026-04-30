"""
BLIP-AI Investigation Engine
=============================
Orchestrates the investigation workflow.
Takes an alert, runs all relevant playbook queries,
scores confidence, and produces a structured finding.
"""

import os
import json
from datetime import datetime, timezone
from splunk_connector import SplunkConnector

class InvestigationEngine:

    def __init__(self):
        self.splunk = SplunkConnector()
        self.findings = []
        self.confidence = 0.0
        self.alert_type = None
        self.src_ip = None

    def detect_alert_type(self, alert_name):
        """Map alert name to playbook type."""
        alert_lower = alert_name.lower()
        if "brute force" in alert_lower or "ssh" in alert_lower:
            return "brute_force"
        elif "port scan" in alert_lower or "reconnaissance" in alert_lower:
            return "network_recon"
        elif "privilege escalation" in alert_lower or "euid" in alert_lower:
            return "privilege_escalation"
        elif "persistence" in alert_lower or "cron" in alert_lower \
             or "systemd" in alert_lower or "startup" in alert_lower \
             or "ssh key" in alert_lower:
            return "persistence"
        elif "credential" in alert_lower or "shadow" in alert_lower:
            return "credential_access"
        else:
            return "unknown"
       elif "enumeration" in alert_lower or "service" in alert_lower:
            return "network_recon"
    def investigate(self, alert_name, hours=4):
        """
        Main investigation loop.
        Run all relevant queries and build findings.
        """
        print(f"\n{'='*60}")
        print(f"BLIP-AI Investigation Starting")
        print(f"Alert: {alert_name}")
        print(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"{'='*60}")

        self.alert_type = self.detect_alert_type(alert_name)
        print(f"\nPlaybook selected: {self.alert_type}")

        # Always run all checks — build complete picture
        evidence = {
            "alert_name": alert_name,
            "alert_type": self.alert_type,
            "investigation_time": datetime.now(timezone.utc).isoformat(),
            "checks": {}
        }

        # Step 1 — Check for prior reconnaissance
        print("\n[1/5] Checking for prior reconnaissance...")
        recon = self.splunk.check_recon_campaign(hours=hours)
        if recon:
            evidence["checks"]["reconnaissance"] = {
                "detected": True,
                "campaigns": recon,
                "confidence_contribution": 0.20
            }
            self.confidence += 0.20
            print(f"      ✅ Recon detected — {recon[0].get('campaign_summary')}")
        else:
            evidence["checks"]["reconnaissance"] = {"detected": False}
            print(f"      ➖ No reconnaissance detected")

        # Step 2 — Check for brute force
        print("\n[2/5] Checking for brute force activity...")
        brute = self.splunk.check_ssh_brute_force(hours=hours)
        if brute:
            top = brute[0]
            evidence["checks"]["brute_force"] = {
                "detected": True,
                "src_ip": top.get("src_ip"),
                "attempt_count": top.get("count"),
                "confidence_contribution": 0.25
            }
            self.confidence += 0.25
            self.src_ip = top.get("src_ip")
            print(f"      ✅ Brute force — {top.get('count')} attempts from {top.get('src_ip')}")
        else:
            evidence["checks"]["brute_force"] = {"detected": False}
            print(f"      ➖ No brute force detected")

        # Step 3 — Check for privilege escalation
        print("\n[3/5] Checking for privilege escalation...")
        escalation = self.splunk.check_privilege_escalation(hours=hours)
        if escalation:
            top = escalation[0]
            evidence["checks"]["privilege_escalation"] = {
                "detected": True,
                "auid": top.get("auid"),
                "processes": top.get("processes"),
                "confidence_contribution": 0.35
            }
            self.confidence += 0.35
            print(f"      ✅ Escalation confirmed — AUID: {top.get('auid')}")
        else:
            evidence["checks"]["privilege_escalation"] = {"detected": False}
            print(f"      ➖ No escalation detected")

        # Step 4 — Check for persistence
        print("\n[4/5] Checking for persistence mechanisms...")
        persistence = self.splunk.check_persistence(hours=hours)
        if persistence:
            top = persistence[0]
            evidence["checks"]["persistence"] = {
                "detected": True,
                "mechanisms": top.get("mechanisms"),
                "tools": top.get("tools"),
                "confidence_contribution": 0.25
            }
            self.confidence += 0.25
            print(f"      ✅ Persistence detected — {top.get('mechanisms')}")
        else:
            evidence["checks"]["persistence"] = {"detected": False}
            print(f"      ➖ No persistence detected")

        # Step 5 — Check for port scan
        print("\n[5/5] Checking for sensitive service enumeration...")
        scan = self.splunk.check_port_scan(hours=hours)
        if scan:
            top = scan[0]
            evidence["checks"]["port_scan"] = {
                "detected": True,
                "src_ip": top.get("src_ip"),
                "unique_ports": top.get("unique_ports"),
                "confidence_contribution": 0.15
            }
            self.confidence += 0.15
            if not self.src_ip:
                self.src_ip = top.get("src_ip")
            print(f"      ✅ Port scan — {top.get('unique_ports')} unique ports from {top.get('src_ip')}")
        else:
            evidence["checks"]["port_scan"] = {"detected": False}
            print(f"      ➖ No port scan detected")

        # Cap confidence at 1.0
        self.confidence = min(self.confidence, 1.0)
        evidence["confidence_score"] = round(self.confidence, 2)
        evidence["src_ip"] = self.src_ip

        # Determine verdict
        evidence["verdict"] = self.determine_verdict()
        evidence["kill_chain"] = self.build_kill_chain(evidence["checks"])
        evidence["recommended_actions"] = self.get_recommendations(evidence)

        self.findings = evidence
        return evidence

    def determine_verdict(self):
        """Score confidence into a verdict."""
        if self.confidence >= 0.90:
            return "CRITICAL — Confirmed attack chain"
        elif self.confidence >= 0.70:
            return "HIGH — Strong indicators of compromise"
        elif self.confidence >= 0.50:
            return "MEDIUM — Suspicious activity detected"
        elif self.confidence >= 0.30:
            return "LOW — Anomalous activity worth monitoring"
        else:
            return "INFORMATIONAL — No significant threat detected"

    def build_kill_chain(self, checks):
        """Build MITRE kill chain from detected stages."""
        chain = []
        if checks.get("reconnaissance", {}).get("detected"):
            chain.append("T1046 — Network Reconnaissance")
        if checks.get("brute_force", {}).get("detected"):
            chain.append("T1110 — Brute Force")
        if checks.get("privilege_escalation", {}).get("detected"):
            chain.append("T1548 — Privilege Escalation")
        if checks.get("persistence", {}).get("detected"):
            chain.append("T1053/T1543/T1546 — Persistence")
        return chain if chain else ["No kill chain stages confirmed"]

    def get_recommendations(self, evidence):
        """Generate recommended actions based on findings."""
        actions = []
        checks = evidence.get("checks", {})

        if checks.get("reconnaissance", {}).get("detected"):
            actions.append("Block scanning source IP at OPNsense firewall")
        if checks.get("brute_force", {}).get("detected"):
            src = checks["brute_force"].get("src_ip")
            actions.append(f"Block {src} at OPNsense — active brute force source")
            actions.append("Review auth.log for successful logins from same IP")
        if checks.get("privilege_escalation", {}).get("detected"):
            actions.append("Audit sudoers for NOPASSWD entries")
            actions.append("Check for SUID binaries: find / -perm -4000 -type f")
        if checks.get("persistence", {}).get("detected"):
            actions.append("Audit authorized_keys for unauthorized entries")
            actions.append("Review root crontab: sudo crontab -l")
            actions.append("Check systemd services: ls -la /etc/systemd/system/*.service")
            actions.append("Inspect .bashrc for injected code: tail -5 ~/.bashrc")
        if not actions:
            actions.append("Continue monitoring — no immediate action required")

        return actions

    def print_report(self):
        """Print formatted investigation report to terminal."""
        if not self.findings:
            print("No investigation run yet.")
            return

        f = self.findings
        print(f"\n{'='*60}")
        print(f"BLIP-AI INVESTIGATION REPORT")
        print(f"{'='*60}")
        print(f"Alert:       {f.get('alert_name')}")
        print(f"Type:        {f.get('alert_type')}")
        print(f"Source IP:   {f.get('src_ip', 'Not identified')}")
        print(f"Time:        {f.get('investigation_time')}")
        print(f"Confidence:  {f.get('confidence_score')} / 1.0")
        print(f"\nVERDICT: {f.get('verdict')}")

        print(f"\nKill Chain Detected:")
        for stage in f.get("kill_chain", []):
            print(f"  → {stage}")

        print(f"\nDetection Summary:")
        for check, result in f.get("checks", {}).items():
            status = "✅ DETECTED" if result.get("detected") else "➖ Clean"
            print(f"  {check.replace('_', ' ').title():<30} {status}")

        print(f"\nRecommended Actions:")
        for i, action in enumerate(f.get("recommended_actions", []), 1):
            print(f"  {i}. {action}")

        print(f"\n{'='*60}")
        print(f"Investigation complete.")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    engine = InvestigationEngine()

    # Test with the most recent alert from your lab
    test_alert = "Privilege Escalation Confirmed (euid=0 Non-Root User)"
    evidence = engine.investigate(test_alert, hours=24)
    engine.print_report()
