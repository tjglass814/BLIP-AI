# BLIP-AI — Behavioral Log Investigation Platform — Artificial Intelligence

> **Autonomous SOC Investigation Platform** — correlates multi-source security telemetry, reconstructs attack kill chains, and generates enterprise-grade incident response reports powered by Claude AI reasoning.

---

## What Is BLIP-AI

BLIP-AI is an autonomous security investigation platform that sits above your SIEM as an intelligence and reasoning layer. When Splunk fires an alert, BLIP-AI automatically:

1. Queries five detection domains across Linux audit, authentication, and network telemetry
2. Correlates findings across the full Lockheed Martin Cyber Kill Chain
3. Scores investigation confidence with weighted evidence factors
4. Sends structured evidence to Claude AI for expert-level reasoning
5. Produces a unified enterprise-grade IR report in under 2 minutes

The goal is not to replace analysts — it is to eliminate Tier 1 triage time and give analysts a pre-built, evidence-grounded investigation to work from rather than starting from scratch.

> **V1.1 Status:** Core investigation loop operational. Five detection domains active. Claude reasoning layer live. Continuous monitoring mode running. Full enterprise IR reports with kill chain, IOC extraction, detection coverage gaps, and confidence breakdown.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Data Sources                          │
│  auditd (host)  │  linux_secure (auth)  │  OPNsense     │
│  filterlog (network)                                     │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Splunk Enterprise 10.2.2                    │
│  827,553+ events ingested  │  15 detection rules active  │
└─────────────────────────┬───────────────────────────────┘
                          │ REST API
                          ▼
┌─────────────────────────────────────────────────────────┐
│              BLIP-AI Investigation Engine                │
│                                                          │
│  splunk_connector.py  →  investigation_engine.py         │
│  Five detection checks  │  Confidence scoring            │
│  Kill chain mapping     │  Evidence tiering              │
└─────────────────────────┬───────────────────────────────┘
                          │ Structured findings
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Claude AI Reasoning Layer                   │
│              claude_analyst.py                           │
│                                                          │
│  Kill chain analysis    │  Evidence tiers                │
│  MITRE ATT&CK mapping   │  Detection coverage gaps       │
│  IOC extraction         │  Confidence breakdown          │
│  Tiered priority actions│  Analyst notes                 │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│         Unified IR Report + JSON Archive                 │
│  11-section enterprise report  │  reports/*.json         │
└─────────────────────────────────────────────────────────┘
```

---

## Detection Domains

BLIP-AI queries five detection domains on every investigation:

| Domain | Source | What It Detects | MITRE |
|---|---|---|---|
| Network Reconnaissance | OPNsense filterlog | Port scan campaigns, sensitive service enumeration, repeated campaign behavior | T1046 |
| SSH Brute Force | linux_secure | Credential stuffing, failed auth volume, breach confirmation | T1110, T1078, T1021.004 |
| Privilege Escalation | auditd SYSCALL | euid=0 from non-root, SUID exploitation, sudo LOLBins | T1548.001, T1548.003 |
| Persistence | auditd | SSH authorized keys, cron jobs, systemd services, .bashrc injection | T1098.004, T1053.003, T1543.002, T1546.004 |
| Post-Exploitation | auditd | Credential harvesting, exfil tools, log tampering, backdoor accounts | T1552.001, T1070.002, T1105, T1136.001 |

---

## Investigation Playbooks

Each detection domain has a corresponding playbook defining investigation steps, confidence weights, false positive rules, verdict logic, and cross-playbook correlation modifiers.

```
playbooks/
├── brute_force.py          # T1110, T1078, T1021.004
├── privilege_escalation.py # T1548.001/003, T1552.001, T1070.002, T1105, T1136.001
├── persistence.py          # T1098.004, T1053.003, T1543.002, T1546.004
└── network_recon.py        # T1046 — V2.0 with campaign persistence detection
```

Each playbook defines:
- SPL queries for every investigation step
- Confidence weight per evidence factor
- False positive suppression rules
- Verdict thresholds and auto-response conditions
- Cross-playbook correlation modifiers — e.g. recon followed by escalation from the same IP raises confidence across both playbooks

---

## Investigation Report Structure

Every BLIP-AI investigation produces an 11-section unified report:

```
1.  Executive Summary
2.  Incident Severity and Business Impact
3.  Attack Timeline (chronological reconstruction)
4.  Evidence Tiers (CONFIRMED / SUSPECTED / NOT VERIFIED)
5.  Cyber Kill Chain Analysis (all 7 Lockheed Martin phases)
6.  MITRE ATT&CK Mapping (technique-level with status and evidence)
7.  Detection Coverage Summary (ATT&CK gap analysis table)
8.  Confidence Score Breakdown (weighted factor table with raise/lower analysis)
9.  Indicators of Compromise (IPs, ports, accounts, tools, file paths, signatures)
10. Priority Actions (IMMEDIATE / SHORT TERM / REMEDIATION with executable bash commands)
11. Analyst Notes (inferences flagged, evidence gaps, manual verification checklist)
```

Reports are saved as structured JSON to `reports/` for downstream integration.

---

## Screenshots

### Splunk Connector — Data Pipeline Verified

<img width="1314" height="357" alt="Screenshot 2026-04-29 at 4 37 58 PM" src="https://github.com/user-attachments/assets/eac50770-edb2-4fc5-a984-d5ef0fd8c0fc" />

### Attack Simulation — Brute Force and Nmap

<img width="828" height="515" alt="Screenshot 2026-04-30 at 4 46 17 PM" src="https://github.com/user-attachments/assets/a29219c3-1ec4-4bfa-9dee-74dd077f8da7" />

### Attack Simulation — Privilege Escalation via sudo vim

<img width="828" height="143" alt="Screenshot 2026-04-30 at 4 46 33 PM" src="https://github.com/user-attachments/assets/53583800-ae9f-4dc8-88b2-0f87e6f730ea" />

### BLIP-AI V1.1 — Full Unified IR Report

<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 10 44 PM" src="https://github.com/user-attachments/assets/9b710e22-12dc-4bd5-8bce-911e7c33a52b" />
<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 10 52 PM" src="https://github.com/user-attachments/assets/9ac80e24-5a02-4495-9c84-d05e0dd14c84" />
<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 11 01 PM" src="https://github.com/user-attachments/assets/eaef3928-59fc-4f7b-86c3-fd2a79af2696" />
<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 11 45 PM" src="https://github.com/user-attachments/assets/54367487-3d26-444a-8b11-8c8c5cc4dad1" />
<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 11 52 PM" src="https://github.com/user-attachments/assets/96051510-adb4-4f82-9738-e8077b31938b" />
<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 12 00 PM" src="https://github.com/user-attachments/assets/cad92513-631d-4949-9550-87910638a377" />
<img width="1509" height="912" alt="Screenshot 2026-05-01 at 5 12 05 PM" src="https://github.com/user-attachments/assets/d970bee8-35e0-4479-ab25-d446537ba24c" />

---

## Confidence Scoring Engine

Confidence is calculated by summing weighted evidence factors across all five detection domains:

| Factor | Weight | Condition |
|---|---|---|
| SSH brute force confirmed | +0.25 | Direct evidence in auth logs |
| Privilege escalation detected | +0.35 | euid=0 from non-root via auditd kernel records |
| Port scan confirmed | +0.15 | OPNsense filterlog evidence |
| Recon campaign confirmed | +0.20 | Multiple scan windows in 4-hour lookback |
| Persistence detected | +0.25 | Any persistence mechanism confirmed |
| Successful login not verified | -0.10 | Auth.log gap |
| Escalation attribution unresolved | -0.10 | Legitimate admin ambiguity |

**Verdict thresholds:**

| Score | Verdict |
|---|---|
| 0.90+ | CRITICAL — Confirmed attack chain |
| 0.70-0.89 | HIGH — Strong indicators of compromise |
| 0.50-0.69 | MEDIUM — Suspicious activity detected |
| 0.30-0.49 | LOW — Anomalous activity worth monitoring |
| < 0.30 | INFORMATIONAL |

**Auto-response threshold:** 0.90 — triggers IP block at OPNsense, TheHive case creation, PDF report (V3+)

---

## Installation

### Prerequisites

```
Python 3.12+
Splunk Enterprise with REST API enabled on port 8089
Anthropic API key — console.anthropic.com
```

### Setup

```bash
git clone https://github.com/tjglass814/BLIP-AI.git
cd BLIP-AI
pip3 install -r requirements.txt --break-system-packages
```

### Configuration

```bash
mkdir -p config
nano config/.env
```

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here
SPLUNK_HOST=127.0.0.1
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your-splunk-password
SPLUNK_INDEX=main
```

```bash
chmod 600 config/.env
```

### Verify Connections

```bash
python3 test_connections.py
```

Expected:
```
✅ Anthropic API:  Connected
✅ Splunk Auth:    Connected
✅ Splunk Search:  Connected
🟢 All systems go. BLIP-AI is ready.
```

---

## Usage

### Single Investigation — Most Recent Alert

```bash
python3 blip_ai.py
```

### Investigate Specific Alert by Name

```bash
python3 blip_ai.py "SSH Brute Force Detection"
python3 blip_ai.py "Privilege Escalation Confirmed (euid=0 Non-Root User)"
python3 blip_ai.py "Repeated Network Reconnaissance Campaign Detected"
```

### Continuous Monitoring Mode

```bash
python3 blip_ai.py monitor
```

Polls Splunk for new triggered alerts every 5 minutes and automatically investigates each one. Press `Ctrl+C` to stop.

---

## Lab Infrastructure

| Component | Details |
|---|---|
| Hardware | Dell OptiPlex 7060 Micro — i5-8500T, 32GB RAM, 512GB NVMe |
| Hypervisor | Proxmox VE 9.1.1 |
| SIEM | Splunk Enterprise 10.2.2 on Ubuntu 24.04 |
| Attacker | Kali Linux VM — 10.10.10.132 |
| Firewall | OPNsense 26.1.2 — 10.10.10.1 / 192.168.1.214 |
| Network | Isolated 10.10.10.x lab segment |
| AI Reasoning | Anthropic Claude Sonnet 4.6 |
| Remote Access | Tailscale mesh VPN |

---

## Project Structure

```
BLIP-AI/
├── blip_ai.py                  # Main orchestrator — banner, pipeline, monitoring mode
├── splunk_connector.py         # Splunk REST API — alert polling, SPL query execution
├── investigation_engine.py     # Evidence gathering — 5 checks, scoring, kill chain
├── claude_analyst.py           # Claude AI reasoning — 11-section unified IR report
├── test_connections.py         # Splunk and Anthropic connection verification
├── requirements.txt
├── .gitignore                  # config/.env and reports/ excluded
├── config/
│   └── .env                   # Credentials — never committed
├── playbooks/
│   ├── brute_force.py
│   ├── privilege_escalation.py
│   ├── persistence.py
│   └── network_recon.py
└── reports/
    └── *.json                 # Auto-generated investigation reports
```

---

## Detection Engineering Foundation

BLIP-AI's detection logic is built on 5 completed lab projects across 2 domains with 30 custom auditd rules, 15 Splunk behavioral detection rules, and 827,553+ ingested events. Full documentation, attack simulations, SPL queries, and CySA+ mapping in the companion repository:

**[Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)**

---

## Roadmap

See **[ROADMAP.md](ROADMAP.md)** for the full version timeline.

**Current:** V1.1 — Core autonomous investigation loop with unified Claude-powered IR reports

**Next:** V2 — Entity memory, Wazuh/Zeek/Snort telemetry, threat intelligence enrichment, TheHive integration

---

## Author

**Taylor Glass** — Virginia Tech Cybersecurity Graduate | Security+ | BTL1

- GitHub: [tjglass814](https://github.com/tjglass814)
- LinkedIn: [linkedin.com/in/taylorglass](https://linkedin.com/in/taylorglass)
- Homelab Repo: [Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)

---

*All attack simulations were conducted in an isolated homelab environment against systems I own and control.*
