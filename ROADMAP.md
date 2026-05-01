# BLIP-AI Roadmap

> Building toward a full-stack autonomous SOC operating platform — investigation intelligence, behavioral correlation, security memory, workflow automation, and adversary simulation.

---

## Current Version

### V1.1 — Core Investigation Loop ✅ LIVE
**Status:** Operational

- Splunk REST API connector — alert polling and SPL query execution
- Five detection domain checks — network recon, brute force, privilege escalation, persistence, post-exploitation
- Weighted confidence scoring engine
- Claude Sonnet 4.6 reasoning layer — 11-section unified IR reports
- Full Lockheed Martin kill chain analysis across all 7 phases
- MITRE ATT&CK mapping with CONFIRMED / SUSPECTED / NOT VERIFIED evidence tiers
- Detection coverage gap analysis
- IOC extraction — IPs, ports, accounts, tools, file paths, signatures
- Confidence score breakdown with raise/lower factor analysis
- Tiered priority actions — IMMEDIATE / SHORT TERM / REMEDIATION with bash commands
- Analyst notes — inferences flagged, evidence gaps identified
- JSON report archiving
- Continuous monitoring mode — auto-investigates new alerts every 5 minutes
- Four investigation playbooks — brute_force, privilege_escalation, persistence, network_recon

**Metrics:**
- Investigation time: ~100 seconds end-to-end
- Events analyzed: 827,553+
- Detection rules active: 15
- Audit rules deployed: 30
- MITRE techniques covered: T1046, T1110, T1078, T1021.004, T1548, T1552, T1070, T1105, T1136, T1098, T1053, T1543, T1546

---

## Upcoming Versions

---

### V2 — Multi-Source Intelligence
**Target:** Domain 2 + Domain 4 completion

**New Capabilities:**
- Wazuh HIDS telemetry connector — host-based intrusion detection data
- Zeek network monitoring integration — network behavior analysis
- Snort/Suricata IDS alert ingestion — signature-based network detection
- LimaCharlie EDR integration — endpoint detection and response telemetry
- Entity memory engine (SQLite) — BLIP-AI remembers prior incidents involving the same IPs, users, and hosts
- Threat intelligence enrichment — automatic VirusTotal, AbuseIPDB, and Shodan lookups on IOCs
- TheHive case management integration — auto-creates cases from high-confidence investigations
- DNS tunneling detection playbook
- Data exfiltration detection playbook
- Lateral movement detection playbook
- Cross-source kill chain correlation — same attacker IP appearing across Wazuh, Zeek, Snort, and Splunk

**New Playbooks:** dns_tunneling, data_exfiltration, lateral_movement, wazuh_hids

---

### V3 — SOAR and Workflow Automation
**Target:** Domain 5 completion

**New Capabilities:**
- Tines workflow engine integration — visual playbook automation
- Automated IP blocking at OPNsense when confidence >= 0.90
- Slack and email alert notifications with investigation summaries
- Automated threat intelligence enrichment pipeline
- Wazuh active response triggers — BLIP-AI-initiated host isolation
- Confidence-based response tiering — different automation at 0.70, 0.85, 0.90
- Honeypot integration — deception-based detection feeding investigation context
- DNS sinkhole analytics — malware C2 domain intelligence
- Workflow audit logging — every automated action recorded and reversible

**New Playbooks:** auto_response, workflow_orchestration

---

### V4 — Windows and Active Directory
**Target:** Domain 3 completion

**New Capabilities:**
- Windows Event Log connector
- Sysmon telemetry integration — process creation, network connections, registry modifications
- Active Directory attack playbooks — Kerberoasting, Pass the Hash, BloodHound enumeration
- Cross-platform kill chain — Linux initial access chaining into Windows lateral movement
- DCSync detection
- Golden and Silver Ticket detection
- LSASS credential dumping detection
- Group Policy abuse detection
- Domain compromise investigation workflow

**New Playbooks:** kerberoasting, pass_the_hash, ad_persistence, domain_recon, lsass_dumping

---

### V5 — Security Knowledge Graph
**Target:** Post-Domain 3

**New Capabilities:**
- Neo4j graph database deployment
- Entity relationship mapping — IPs, users, hosts, processes, alerts, techniques all connected
- Persistent adversary tracking across incidents — BLIP-AI remembers an IP was involved in a campaign 3 months ago
- Attack path visualization
- "Show every host touched by this IP" cross-incident queries
- Behavioral drift detection — deviations from established entity baselines flagged automatically
- Long-term threat actor profiling
- Investigation memory — prior analyst decisions and verdicts feed future confidence scoring

---

### V6 — Detection-as-Code Platform
**Target:** Post-V5

**New Capabilities:**
- YAML detection rule format with ATT&CK tagging, severity, confidence, and false positive documentation
- Detection unit testing framework — automated validation that rules fire on known-bad and stay silent on known-good
- CI/CD detection pipeline — push a new YAML rule, automated tests run, coverage scores update
- ATT&CK coverage heatmap — visual representation of detection gaps across all techniques
- Purple team validation engine — simulate attack, confirm detection fires, measure MTTD
- Detection quality metrics — true positive rate, false positive rate, MTTD per rule
- Detection version control — every rule change tracked, rollback supported

---

### V7 — Web Platform
**Target:** Post-V6

**New Capabilities:**
- FastAPI backend
- React + TypeScript frontend with Tailwind and shadcn/ui
- Live investigation dashboard — active alerts, confidence scores, investigation status
- Attack graph visualization — entity relationships rendered as interactive graphs
- ATT&CK matrix heatmap — coverage and recent activity overlay
- Timeline view — chronological investigation reconstruction
- Case management UI — investigation archive, analyst notes, status tracking
- Workflow builder — visual drag-and-drop playbook editor
- Threat hunting console — free-form query interface with BLIP-AI assistance
- Detection management UI — create, test, and deploy YAML detection rules

---

### V8 — Multi-Agent SOC
**Target:** Post-V7

**New Capabilities:**
- Specialized AI agent roles replacing the single Claude analyst call
- Threat Hunter agent — proactive hypothesis generation, behavioral anomaly focus
- IR Lead agent — containment priority, business impact, escalation decisions
- Detection Engineer agent — coverage gap analysis, new rule recommendations
- Malware Analyst agent — process behavior, network IOCs, binary triage
- Threat Intel agent — adversary attribution, TTP correlation, campaign tracking
- Agent collaboration — agents compare findings, confidence-weight disagreements
- Orchestration layer — selects which agents run based on alert type and context

---

### V9 — Adversary Simulation Engine
**Target:** Post-V8

**New Capabilities:**
- Atomic Red Team integration — automated ATT&CK technique execution
- Caldera adversary emulation — full campaign simulation
- Detection validation loop — BLIP-AI runs attack, validates detection fired, scores coverage
- Investigation replay engine — re-run any past investigation from raw logs, get reproducible output
- Purple team scoring — coverage percentage per ATT&CK tactic and technique
- "CI/CD for detections" — every detection rule validated against simulation before deployment
- Attack path prediction — graph-based analysis of likely next attacker moves

---

### V10 — Enterprise SOC Platform
**Target:** Year 2+

**New Capabilities:**
- Cloud telemetry — AWS CloudTrail, GuardDuty, Azure Sentinel
- UEBA — user and entity behavior analytics with anomaly scoring
- Threat hunting workbench — hypothesis-driven hunting with BLIP-AI assistance
- Full compliance mapping — SOC 2, NIST CSF, MITRE ATT&CK coverage reporting
- Multi-tenancy architecture consideration
- Open source release with community detection sharing
- Kubernetes deployment option
- Redpanda event bus for high-volume ingestion

---

## Infrastructure Upgrade Path

| Phase | Investment | Trigger |
|---|---|---|
| V1-V3 | $0 — current OptiPlex handles everything | No upgrade needed |
| V4-V5 | ~$500-800 — 32GB RAM upgrade + second SSD | Windows AD VM requires more memory |
| V6-V7 | ~$800-1500 — Second machine for web platform | BLIP-AI platform separate from Splunk server |
| V8+ | ~$2000-3000 — Proper homelab rack + NAS | Multi-node deployment, persistent storage |

---

## Domain Completion Status

| Domain | Status | BLIP-AI Version |
|---|---|---|
| Domain 1 — Linux & SIEM | ✅ 5/6 projects complete | V1.1 |
| Domain 2 — Network Security | 🔄 2/10 projects complete | V2 |
| Domain 3 — Windows & Active Directory | ⏳ Not started | V4 |
| Domain 4 — Endpoint Security | ⏳ Not started | V2 |
| Domain 5 — SOAR & Automation | ⏳ Not started | V3 |
| Domain 6 — Threat Intelligence | ⏳ Not started | V2 |
| Domain 7 — Vulnerability Management | ⏳ Not started | V3 |
| Domain 8 — Cloud Security | ⏳ Not started | V10 |
| Domain 9 — Forensics & IR | ⏳ Not started | V5+ |
| Domain 10 — Purple Team | ⏳ Not started | V9 |

Full project documentation for all domains: **[Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)**

---

*Roadmap is subject to change as the platform evolves. Each version ships working capabilities — done beats perfect at every stage.*
