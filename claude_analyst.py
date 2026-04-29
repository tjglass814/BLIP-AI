"""
BLIP-AI Claude Analyst
======================
The reasoning layer. Takes structured Splunk findings
and asks Claude to reason about them like a senior SOC analyst.
This is what transforms raw detection data into
intelligent investigation narratives.
"""

import os
import json
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
        Send investigation findings to Claude for reasoning.
        Returns enriched analysis as a string.
        """

        # Build the prompt from findings
        prompt = self._build_prompt(findings)

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                system="""You are BLIP-AI, an autonomous SOC analyst assistant.
You receive structured security investigation findings from a Linux environment
and provide expert analysis. Your responses are concise, technical, and actionable.
You think like a senior threat analyst — connecting evidence across the kill chain,
assessing attacker intent, and prioritizing response actions by severity.
Always structure your response with: Situation Summary, Kill Chain Analysis,
Attacker Intent Assessment, and Priority Actions.""",
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
        """Convert findings dict into a clear prompt for Claude."""

        checks = findings.get("checks", {})
        kill_chain = findings.get("kill_chain", [])
        confidence = findings.get("confidence_score", 0)
        verdict = findings.get("verdict", "Unknown")
        src_ip = findings.get("src_ip", "Unknown")

        # Build evidence summary
        evidence_lines = []

        recon = checks.get("reconnaissance", {})
        if recon.get("detected"):
            campaigns = recon.get("campaigns", [{}])
            summary = campaigns[0].get("campaign_summary", "Unknown")
            evidence_lines.append(f"- Network reconnaissance: {summary}")

        brute = checks.get("brute_force", {})
        if brute.get("detected"):
            evidence_lines.append(
                f"- SSH brute force: {brute.get('attempt_count')} attempts from {brute.get('src_ip')}"
            )

        escalation = checks.get("privilege_escalation", {})
        if escalation.get("detected"):
            evidence_lines.append(
                f"- Privilege escalation confirmed: AUID={escalation.get('auid')} "
                f"processes={escalation.get('processes')}"
            )

        persistence = checks.get("persistence", {})
        if persistence.get("detected"):
            evidence_lines.append(
                f"- Persistence mechanisms: {persistence.get('mechanisms')}"
            )

        port_scan = checks.get("port_scan", {})
        if port_scan.get("detected"):
            evidence_lines.append(
                f"- Port scan: {port_scan.get('unique_ports')} unique ports "
                f"from {port_scan.get('src_ip')}"
            )

        evidence_text = "\n".join(evidence_lines) if evidence_lines \
            else "No significant evidence detected"

        prompt = f"""BLIP-AI Security Investigation Report

Alert Triggered: {findings.get('alert_name')}
Source IP: {src_ip}
Confidence Score: {confidence}/1.0
Initial Verdict: {verdict}

Evidence Collected:
{evidence_text}

Kill Chain Stages Detected:
{chr(10).join(f'- {stage}' for stage in kill_chain)}

Environment Context:
- Target: Ubuntu Server (splunk-server) at 10.10.10.198
- Attacker: Kali Linux at 10.10.10.132
- SIEM: Splunk Enterprise with auditd and OPNsense logs
- Lab: Isolated 10.10.10.x segment behind OPNsense firewall

Based on this evidence, provide your SOC analyst assessment.
Be specific about what the attacker likely did, what their objective was,
and what the defender must do immediately."""

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
        print("\nAPI not ready yet — run this again after billing is resolved.")
