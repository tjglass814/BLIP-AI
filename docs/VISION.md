# BLIP-AI — Vision

> This document describes the **end state**. For the phased, near-term execution
> plan, see [BUILD-PLAN.md](BUILD-PLAN.md). The build proceeds in small iterations;
> this is the destination they aim at.

---

## The Vision in One Paragraph

BLIP-AI (Behavioral Log Investigation Platform — Artificial Intelligence) is being
built as a **governed, fully autonomous SOC platform** that monitors telemetry
across Linux, Windows, network, and cloud environments; correlates behavioral
signals across domains into coherent attack stories; investigates them on its own;
remembers the entities and incidents it has seen; enriches evidence with external
intelligence; makes confidence-based, policy-governed decisions; takes controlled
defensive action; verifies the result; and can **explain and prove every conclusion
it reaches.** The homelab is the proving ground. The GitHub repo is the portfolio.

## Not This — This

The whole project turns on one distinction. The wrong thing to build:

```
Alert  →  LLM  →  "looks malicious"  →  execute
```

That is a demo. The right thing to build:

```
Normalize → Correlate → Investigate → Enrich → Validate
   → Risk → Policy → Act → Verify → Remember
```

That is an autonomous SOC: a system that reasons over security evidence as a
connected whole, governed at every step, and auditable end to end.

## The Full Architecture (end state)

```
┌───────────────────────────────────────────────────────────────┐
│                        BLIP-AI WEB SOC                         │
│  Dashboard │ Alerts │ Incidents │ Entities │ Graph │ Hunting   │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                     INTELLIGENCE LAYER                         │
│  Multi-Agent Investigation · Confidence Scoring               │
│  Cross-Domain Correlation · Entity Memory · Threat Intel       │
│  Attack-State Modeling · MITRE Mapping                         │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                    DETECTION / ANALYTICS                       │
│  Splunk · Behavioral Rules · Signatures · Anomaly Detection   │
└───────────────────────────────┬───────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   ┌─────────┐            ┌─────────┐            ┌─────────┐
   │ Endpoint│            │ Network │            │  Cloud  │
   │ auditd  │            │ Zeek    │            │CloudTrail│
   │ Sysmon  │            │ Suricata│            │ IAM     │
   │ Wazuh   │            │ OPNsense│            │Container│
   └─────────┘            └─────────┘            └─────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │    RESPONSE LAYER     │
                    │ TheHive · Cortex ·    │
                    │ Tines · OPNsense ·    │
                    │ EDR containment       │
                    └───────────────────────┘
```

## The Capabilities, in Plain Terms

**Investigation as an evolving story.** A conventional SIEM emits six unrelated
alerts — scan, SSH, session, command, archive, transfer. BLIP-AI reconstructs the
single story behind them:

```
Reconnaissance → Discovery → Access → Execution → Collection → Exfiltration
```

One incident, one timeline, not six loose alerts.

**Entity memory.** An IP is not a stranger every time it appears. BLIP-AI remembers
that `10.10.10.132` scanned four times, moved laterally twice, and touched a
honeypot — so its next action is read in the light of its history, not in isolation.

**The security knowledge graph.** Eventually, entities and their relationships form a
connected map, so the platform can answer questions no log search can:

```
Attacker IP ──scanned──► Target Host ──SSH──► Session
     ──executed──► tar/zip ──staged──► Archive ──sent to──► External IP
```

*"Show me every host contacted by anything that ever touched the honeypot."*

**Explainable, governed autonomy.** BLIP-AI never simply says "I blocked the IP." It
shows the decision basis, the corroborating sources, the confidence, the
reversibility, the verification, and the rollback path. Autonomy without
explainability is dangerous; every autonomous action is evidence-backed and audited.

**Multi-agent future.** The single investigator becomes a coordinated team — a
network specialist, a host specialist, a threat-intel specialist, a correlation
agent, a decision agent, a response agent, and a verification agent — under a
supervisor. This is how the largest commercial platforms are actually built.

**Self-validation.** The platform continuously tests whether it would still catch
the attacks it is supposed to — the purple-team loop built into the product itself.

## The Ultimate Loop

```
Attacker begins reconnaissance
        ▼
BLIP-AI observes weak signals · entity memory recognizes history
        ▼
Agents correlate scanning, access, execution across domains
        ▼
Threat intel enriches · TTPs mapped · confidence calculated
        ▼
Web SOC shows the live incident · case created
        ▼
Confidence crosses the governed threshold
        ▼
Response agent contains · verification confirms
        ▼
Entity graph and memory updated · incident retained as context
```

Not *"this log matched a rule,"* but:

> *"This entity scanned three hosts, accessed one, executed commands, collected
> data, contacted a suspicious destination, and attempted exfiltration. Four
> independent telemetry sources corroborate the attack. Confidence is 0.97. The
> destination has been blocked, the incident documented, and containment verified."*

## The Portfolio Statement

When mature, BLIP-AI demonstrates detection engineering, security architecture,
platform engineering, adversary knowledge, and operational maturity — built from the
ground up. The interview answer is not *"I used a SIEM to detect attacks."* It is:

> *"I built the investigation engine, the correlation and confidence models, the
> governance and policy layer, and the autonomous response platform from the ground
> up — and I can explain and defend every architectural decision I made."*
