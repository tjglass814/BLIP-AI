# BLIP-AI

**Behavioral Log Investigation Platform — Artificial Intelligence**

> Not a SIEM. Not an LLM chatbot. Not just SOAR.
> A **governed security investigation and response platform** that builds
> evidence-backed understanding from heterogeneous security telemetry.

---

## What BLIP-AI Is

BLIP-AI is an autonomous Security Operations Center (SOC) platform. It watches an
environment, notices attacks, investigates them on its own across multiple sources
of telemetry, decides what they mean, and — under strict governance — can respond.
Critically, it can **explain and prove every conclusion it reaches**: every verdict
traces back to concrete evidence and a transparent confidence calculation.

The platform is built on a real detection homelab
([Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)),
which supplies the sensors and detections BLIP-AI reasons over.

## The Core Idea

A traditional SIEM fires a stream of disconnected alerts and leaves a human to
piece them together:

```
Log  →  SIEM Alert  →  Human Analyst  →  Investigation  →  Decision  →  Response
```

BLIP-AI collapses that into an autonomous, governed loop:

```
Telemetry
    │
    ▼
Detection  →  Correlation  →  Investigation  →  Entity Memory
    │                                               │
    ▼                                               ▼
Confidence / Risk  ────────────────────────►  Evidence & Verdict
    │
    ▼
Policy Engine  →  Approval Gate  →  Action  →  Verification  →  Audit
```

The distinction that matters: BLIP-AI does not merely say *"something happened."*
It answers **what happened, who is involved, is it actually malicious, what came
before and after, has this entity been suspicious before, what does the evidence
show, and what should be done** — and, increasingly, it can safely do it.

## Architecture at a Glance

```
┌───────────────────────────────────────────────────────────────┐
│                        BLIP-AI WEB SOC                         │
│   Dashboard │ Incidents │ Entities │ Attack Graph │ Hunting    │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                    INTELLIGENCE / CORE (blip_core)            │
│   Investigation Loop │ Correlation │ Confidence │ MITRE        │
│   Entity Memory │ Policy Engine │ Audit Trail                  │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                     GOVERNED TOOL GATEWAY                      │
│        typed tools · schemas · risk levels · audit             │
└───────────────────────────────┬───────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   ┌─────────┐            ┌─────────┐            ┌─────────┐
   │ Endpoint│            │ Network │            │  Cloud  │
   │ auditd  │            │ Zeek    │            │(planned)│
   │ (EDR*)  │            │ Suricata│            │         │
   └─────────┘            │ OPNsense│            └─────────┘
                          └─────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   RESPONSE LAYER*     │
                    │  block · isolate ·    │
                    │  case · (governed)    │
                    └───────────────────────┘

  * planned — see docs/BUILD-PLAN.md for the phased roadmap
```

## Current Status

| Component | State |
|---|---|
| **P0 — Governed Core** | ✅ Complete — see [docs/architecture/01-governed-core.md](docs/architecture/01-governed-core.md) |
| P1 — Live Investigation | ⏳ Next |
| P2 — Correlation | 📋 Planned |
| P3 — Entity Memory (MVP) | 📋 Planned |
| P4 — Web SOC UI | 📋 Planned |
| P5 — Governed Autonomous Response | 📋 Planned |

The full roadmap — all five axes and the phased plan — is in
**[docs/BUILD-PLAN.md](docs/BUILD-PLAN.md)**.

## Repository Layout

```
BLIP-AI/
├── README.md                     ← you are here
├── blip_core/                    ← the governed platform core (P0, complete)
│   ├── tools/                    ← typed tool gateway + guardrails + registry
│   ├── deterministic/            ← confidence, MITRE, evidence tags, policy
│   ├── llm/                      ← the agentic investigation loop
│   ├── verdict/                  ← the structured verdict schema
│   └── audit/                    ← append-only audit log
├── docs/
│   ├── VISION.md                 ← the long-term end-state vision
│   ├── BUILD-PLAN.md             ← the five-axis phased roadmap
│   └── architecture/             ← per-phase design write-ups
│       └── 01-governed-core.md
├── tests/                        ← unit tests + (growing) scenario harness
└── KNOWN_ISSUES.md
```

## Design Principles

1. **Governed, not autonomous-by-default.** Every action flows through a policy
   engine from day one. The LLM never directly owns authority.
2. **Deterministic where it counts.** Thresholds, confidence math, MITRE mapping,
   and policy are plain code — the LLM interprets and investigates, it does not
   grade its own work.
3. **Evidence & decision traceability.** Every verdict traces to concrete evidence
   and a transparent confidence calculation. No black boxes.
4. **Safety before capability.** Guardrails and audit were built before the engine
   that uses them.
