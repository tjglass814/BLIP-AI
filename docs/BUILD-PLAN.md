# BLIP-AI Build Plan

**Status:** Approved plan of record.
**Identity:** Not a SIEM. Not an LLM chatbot. Not just SOAR. A **governed security
investigation and response platform** that builds evidence-backed understanding
from heterogeneous security telemetry.

This document is the execution roadmap. It is organized as **five axes** sitting on
a shared **foundation (Axis 0)**. The axes are five lenses on one goal: *what you
build, what you feed it, how you keep it safe, how you prove it works, and how you
keep it honest.*

Build proceeds in small, demoable iterations. The **MVP line is the end of Phase 3.**

---

## Axis 0 — The Common Data & Identity Model (foundation)

Underneath all five axes is a single, consistent way of representing security
objects: **entities, events, alerts, findings, evidence, incidents, actions, and
relationships.**

```
                         BLIP-AI
                            │
            ┌───────────────┴───────────────┐
            │                               │
     Entity / Event Model            Evidence Model
            │                               │
            └───────────────┬───────────────┘
                            │
   ┌──────────┬─────────────┼─────────────┬──────────┐
   ▼          ▼             ▼             ▼          ▼
 Platform  Coverage    Governance     Testing    Traceability
 (Axis 1)  (Axis 2)    (Axis 3)      (Axis 4)   (Axis 5)
```

**Why it comes first:** if entities, events, and evidence are represented
consistently, then Splunk, Zeek, Suricata, auditd, Windows, EDR, cloud, threat
intel, the UI, and eventually a Neo4j graph all become **producers and consumers of
the same objects**. Get this right early and everything plugs together; get it
wrong and you spend forever translating between formats. This is the architectural
glue — protect it carefully.

---

## Axis 1 — Platform Maturity (what you build)

The execution roadmap. Each phase is a working, demoable step.

```
              ┌─────────────────┐
              │  P0 Governed    │  ✅ complete
              │     Core        │
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │ P1 Live         │  ⏳ next
              │ Investigation   │
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │ P2 Correlation  │
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │ P3 Entity Memory│
              └────────┬────────┘
                       ▼
                  ┌─────────┐
                  │   MVP   │  ← Autonomous Investigation SOC
                  └────┬────┘
                       ▼
              ┌─────────────────┐
              │ P4 Web SOC UI   │
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │ P5 Governed     │
              │ Autonomous Resp.│
              └────────┬────────┘
                       ▼
     ┌─────────────────────────────────────┐
     │  P6+  parallel expansion tracks      │
     └─────────────────────────────────────┘
```

### P0 — Governed Core ✅
The foundation: an AI investigation engine that can only act through safe,
pre-approved typed tools; computes confidence with deterministic code (never
letting the LLM assert its own score); and logs everything. Full write-up:
[architecture/01-governed-core.md](architecture/01-governed-core.md).

### P1 — Live Investigation ⏳
Connect the engine to real Splunk data and let it investigate an actual alert end
to end, returning an evidence-backed verdict — plus a thin visualization to *see*
the investigation. This is the "it works against real data" milestone. **The test
scenario schema is established here** (even with a single scenario), and the
**governance step is wired into the action path** from the start.

### P2 — Correlation
Teach BLIP-AI to turn scattered signals (scan + login + command + archive + upload)
into **one attack story** with a timeline. This also establishes the **entity
model** — an incident understood as `alert + IP + host + user + process + file +
connection`. This is the capability that separates a real SOC from an alert
forwarder.

### P3 — Entity Memory → **MVP**
Add **persistent history** on top of P2's entity model: an IP that scanned last week
walks in already suspicious. Because P2 already defined the entity model, this is an
extension, not a redesign.

**End of P3 = Autonomous Investigation SOC MVP.** BLIP-AI now detects, correlates
into attack stories, investigates, and remembers — autonomous in *investigation and
reasoning*. (It is **not** yet autonomous in *action* — that is P5. This distinction
is deliberate and defensible.)

### P4 — Web SOC Command Center
The full operational interface: active incidents, clickable attack chains, evidence
timelines, and the drill-down "trace this verdict to the raw log/packet" view.

### P5 — Governed Autonomous Response
The system gains hands — block, isolate, open a case — always through the Axis 3
governance chain. Starts by *recommending*; independence is dialed up by policy.

### P6+ — Industry Expansion (parallel tracks, not a strict sequence)

```
P6+ ┌── Intelligence ──── Threat Intel · Knowledge Graph (Neo4j)
    │
    ├── Environment ───── Windows/AD · Endpoint/EDR · Cloud
    │
    ├── Investigation ─── Digital Forensics
    │
    ├── Architecture ──── Multi-Agent (supervisor + specialists)
    │
    └── Validation ────── Continuous Purple Team
```

These are independent expansions taken on when the lab is ready — Windows/AD is not
inherently "later" than threat intel.

---

## Axis 2 — Detection Coverage (what you feed it)

The platform is the engine; detections are the fuel. This is the telemetry backlog
— **the former 10-domain homelab roadmap, now demoted to a coverage library** you
draw from *after* the platform is built, to test and expand what BLIP-AI can catch.

| Coverage area | State |
|---|---|
| Linux / host behavior (auditd) | ✅ Largely complete |
| Network — Zeek (behavioral) + Suricata (signature) + OPNsense | 🔄 In progress |
| Windows & Active Directory | 📋 Backlog |
| Endpoint / EDR (Wazuh, LimaCharlie) | 📋 Backlog |
| Cloud (CloudTrail, IAM) | 📋 Backlog |
| DNS & covert channels | 📋 Backlog |
| Threat intelligence feeds | 📋 Backlog |

*Axis 1 builds the detective; Axis 2 is everything the detective is trained to
recognize.*

---

## Axis 3 — Governance & Autonomy (how you keep it safe)

**An architectural invariant from P0 onward.** Every proposed action — even in early
phases when the system cannot act — flows through the same fixed chain:

```
Agent Recommendation
        ▼
   Policy Engine
        ▼
   Authorization
        ▼
   Approval Gate
        ▼
  Action Executor   (records prior state — idempotent, rollback-capable)
        ▼
   Verification
        ▼
   Audit Record
```

**The LLM never directly owns authority.** Autonomy is a dial turned up *by policy*,
per action type — never bolted on:

| Action | Initial | Mature |
|---|---|---|
| IOC enrichment | Human approval | Autonomous |
| Create case | Human approval | Autonomous |
| Collect evidence | Human approval | Autonomous |
| Block IOC | Human approval | Policy-controlled autonomous |
| Isolate host | Human approval | Approval required |
| Disable account | Human approval | Approval required |
| **Delete evidence** | **Prohibited** | **Prohibited** |

"Prohibited" is a **first-class policy category**, not merely an implementation
restriction.

---

## Axis 4 — Testing & Validation (how you prove it works)

Grows alongside the platform, from casual to rigorous:

```
Manual validation  →  Scenario replay  →  Regression suite  →  Continuous
                                                              adversary validation
```

The **scenario format is established during P1**, even with one or two scenarios:

```
tests/scenarios/
├── network_scan/
├── ssh_bruteforce/
├── privilege_escalation/
├── exfiltration/
└── false_positive/        ← normal activity it must NOT alarm on
```

Each scenario eventually specifies: attack/replay, expected detections, expected
entities, expected correlation, expected verdict, expected severity, expected
evidence, expected response recommendation. Re-run the whole library after every
change so nothing regresses. **The former Domain-10 Purple Team work becomes this
mechanism** — continuous self-validation, not a separate project.

---

## Axis 5 — Evidence & Decision Traceability (how you keep it honest)

Runs through every phase — a quality bar, not a stage. BLIP-AI never says "trust me,
it's malicious." It says *"it's malicious because —"* and shows the receipts:

```
VERDICT: TRUE POSITIVE          CONFIDENCE: 0.94

Evidence:
  E-001  Zeek connection
  E-002  Suricata alert
  E-003  auditd execve
  E-004  file staging event
  E-005  outbound transfer

Correlation:   E-001 → E-003 → E-004 → E-005

Confidence calculation:
  Behavioral correlation      +0.25
  Independent telemetry       +0.20
  Known malicious indicator   +0.20
  Attack-chain completeness   +0.19
  Contradictory evidence      -0.00
                              ------
                               0.84

Trace:  Raw evidence → Finding → Correlation → Decision
        → Policy decision → Action → Verification
```

This is **auditability**, not black-box "explainability" — every verdict traces to
concrete evidence, a transparent confidence calculation, and a click-path to the
raw log or packet behind it.

---

## The MVP Line

**End of Phase 3** is the first "this is a real, working, auditable autonomous
*investigation* SOC" milestone:

> Here is an attack. BLIP-AI receives the detections, correlates them, reconstructs
> the attack story, investigates the evidence, understands the entities involved,
> remembers them for the future — and shows the evidence behind every conclusion.

Everything after — UI, governed response, threat intel, cloud, multi-agent, the
knowledge graph — is the climb from *impressive MVP* to *industry-grade platform*.
