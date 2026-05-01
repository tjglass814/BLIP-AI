# BLIP-AI — Behavioral Log Investigation Platform — Artificial Intelligence

> Autonomous SOC investigation platform — correlates multi-source security telemetry, reconstructs attack kill chains, and generates enterprise-grade incident response reports powered by Claude AI reasoning.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise%2010.2.2-black)
![Claude](https://img.shields.io/badge/Claude-Sonnet%204.6-orange)
![Version](https://img.shields.io/badge/Version-1.1-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## What Is BLIP-AI

BLIP-AI is an autonomous security investigation platform that sits above your SIEM as an intelligence and reasoning layer. When Splunk fires an alert, BLIP-AI:

- Queries five detection domains across Linux audit, authentication, and network telemetry
- Correlates evidence across the full Lockheed Martin Cyber Kill Chain
- Scores investigation confidence with weighted, explainable factors
- Sends structured evidence to Claude AI for expert-level reasoning
- Produces an 11-section enterprise-grade IR report in under 2 minutes

**The core problem it solves:** Tier 1 alert triage takes 45-90 minutes of analyst time per investigation. BLIP-AI does it autonomously in under 2 minutes and produces a more structured, evidence-grounded output than most manual investigations.

---

## Architecture

```
Data Sources (auditd / linux_secure / OPNsense filterlog)
        │
        ▼
Splunk Enterprise — 827,553+ events ingested
        │ REST API
        ▼
Investigation Engine — 5 detection checks, confidence scoring, kill chain
        │ Structured findings
        ▼
Claude AI Reasoning Layer — 11-section unified IR report
        │
        ▼
JSON Report Archive + Continuous Monitoring Mode
```

---

## Current Version — V1.1

**Status:** Operational

| Metric | Value |
|---|---|
| Investigation time | ~100 seconds end-to-end |
| Detection domains | 5 |
| Active Splunk rules | 15 |
| auditd rules deployed | 30 |
| Events ingested | 827,553+ |
| MITRE techniques covered | T1046, T1110, T1078, T1548, T1552, T1070, T1105, T1136, T1098, T1053, T1543, T1546 |
| Report sections | 11 |
| Confidence scoring | Weighted, explainable, raise/lower factor analysis |

**Full V1.1 documentation, screenshots, and metrics:** [Versions/V1/README.md](Versions/V1/README.md)

---

## Quick Start

```bash
git clone https://github.com/tjglass814/BLIP-AI.git
cd BLIP-AI
pip3 install -r requirements.txt --break-system-packages

# Configure credentials
mkdir -p config
nano config/.env
# Add: ANTHROPIC_API_KEY, SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USERNAME, SPLUNK_PASSWORD, SPLUNK_INDEX

# Verify connections
python3 test_connections.py

# Run investigation on most recent alert
python3 blip_ai.py

# Continuous monitoring mode
python3 blip_ai.py monitor
```

---

## Investigation Report Structure

```
 1. Executive Summary
 2. Incident Severity and Business Impact
 3. Attack Timeline
 4. Evidence Tiers — CONFIRMED / SUSPECTED / NOT VERIFIED
 5. Cyber Kill Chain Analysis — all 7 Lockheed Martin phases
 6. MITRE ATT&CK Mapping
 7. Detection Coverage Summary — ATT&CK gap analysis
 8. Confidence Score Breakdown — weighted factor table
 9. Indicators of Compromise
10. Priority Actions — IMMEDIATE / SHORT TERM / REMEDIATION
11. Analyst Notes — inferences flagged, evidence gaps identified
```

---

## Repository Structure

```
BLIP-AI/
├── blip_ai.py                  # Main orchestrator
├── splunk_connector.py         # Splunk REST API connector
├── investigation_engine.py     # Evidence gathering and confidence scoring
├── claude_analyst.py           # Claude AI reasoning and report generation
├── test_connections.py         # Connection verification
├── requirements.txt
├── Versions/
│   └── V1/
│       └── README.md          # Full V1 documentation and screenshots
├── playbooks/
│   ├── brute_force.py
│   ├── privilege_escalation.py
│   ├── persistence.py
│   └── network_recon.py
└── config/
    └── .env                   # Credentials — never committed
```

---

## Roadmap

BLIP-AI is actively developed toward a full-stack autonomous SOC operating platform combining investigation intelligence, security memory, workflow automation, and adversary simulation.

**[Full Roadmap — V1 through V10](ROADMAP.md)**

| Version | Focus | Status |
|---|---|---|
| V1.1 | Core investigation loop + Claude reasoning | ✅ Live |
| V2 | Entity memory, Wazuh/Zeek/Snort, threat intel enrichment | 🔄 Planning |
| V3 | SOAR automation, Tines workflows, auto-response | ⏳ Upcoming |
| V4 | Windows + Active Directory, Sysmon, cross-platform kill chain | ⏳ Upcoming |
| V5 | Neo4j security knowledge graph, adversary tracking | ⏳ Upcoming |
| V6 | Detection-as-code, purple team validation engine | ⏳ Upcoming |
| V7 | Web platform — FastAPI + React + graph visualization | ⏳ Upcoming |
| V8 | Multi-agent SOC — specialized AI investigator roles | ⏳ Upcoming |
| V9 | Adversary simulation engine, investigation replay | ⏳ Upcoming |
| V10 | Cloud telemetry, UEBA, full platform maturity | ⏳ Upcoming |

---

## Detection Engineering Foundation

BLIP-AI's detection logic is built on completed lab projects across 10 planned domains covering Linux, network, Windows, endpoint, SOAR, threat intelligence, vulnerability management, cloud, forensics, and purple team.

Full project documentation, attack simulations, SPL queries, auditd rules, and CySA+ CS0-004 mapping:

**[Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)**

---

## Lab Infrastructure

| Component | Details |
|---|---|
| Hardware | Dell OptiPlex 7060 Micro — i5-8500T, 32GB RAM, 512GB NVMe |
| Hypervisor | Proxmox VE 9.1.1 |
| SIEM | Splunk Enterprise 10.2.2 on Ubuntu 24.04 |
| Attacker | Kali Linux VM — 10.10.10.132 |
| Firewall | OPNsense 26.1.2 |
| Network | Isolated 10.10.10.x lab segment |
| AI Reasoning | Anthropic Claude Sonnet 4.6 |

---

## Author

**Taylor Glass** — Virginia Tech Cybersecurity Graduate | Security+ | BTL1

- GitHub: [tjglass814](https://github.com/tjglass814)
- LinkedIn: [linkedin.com/in/taylorglass](https://linkedin.com/in/taylorglass)
- Homelab: [Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)

---

*All attack simulations conducted in an isolated homelab environment against systems I own and control.*
