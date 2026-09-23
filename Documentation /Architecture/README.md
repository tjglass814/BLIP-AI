# BLIP-AI Architecture — The Autonomous Core

> How BLIP-AI is evolving from a scripted investigation pipeline (V1.1) into a governed
> agent runtime — and why "governed" is the whole point, not a nice-to-have.

---

## What This Is

`blip_core/` is a new package living alongside BLIP-AI's original V1.1 engine
(`blip_ai.py` / `investigation_engine.py` / `claude_analyst.py` / `splunk_connector.py`).
V1.1 is a fixed pipeline: five hardcoded Splunk checks run in sequence, a Python function
sums their weights into a confidence score, and the result is handed to Claude once, at
the end, to write a report. It works, and it stays running untouched.

`blip_core` is where BLIP-AI grows an actual investigator: an agent that decides, alert
by alert, what to check next — choosing its own path through the evidence instead of
running the same five queries every time — while staying inside limits that Python, not
the model, enforces.

## The Central Thesis: Governed, Not Autonomous-by-Default

The obvious way to bolt an LLM onto a SOC pipeline is: **alert → LLM → "this looks
malicious" → LLM executes a response.** That pattern is easy to build and it's how a lot
of "AI SOC" demos work. BLIP-AI's autonomous core is deliberately not built that way, for
three concrete reasons:

1. **A single ungoverned judgment call has real blast radius.** Blocking an IP,
   isolating a host, or opening a case are actions with consequences. Collapsing
   "decide" and "act" into one LLM call means a hallucination, a misread log line, or a
   prompt-injection payload sitting in attacker-controlled log content has a direct path
   to executing something.
2. **A verdict with no audit trail isn't defensible.** "The model said CRITICAL" is not
   an answer a real incident response process can stand behind. Every number and every
   MITRE mapping BLIP-AI produces has to trace back to a specific piece of evidence from
   a specific tool call — that's the difference between a verdict and a guess.
3. **Confidence is arithmetic, not vibes.** An LLM asked to also self-report "how
   confident are you" is estimating its own reliability, which is a different (and much
   less trustworthy) task than interpreting evidence. BLIP-AI keeps those separate: the
   LLM interprets what it found; Python computes what that's worth.

Concretely, "governed" means: the LLM only ever calls typed, schema-validated,
read-only tools (never a shell); every call is logged; confidence and MITRE mapping are
computed deterministically from tagged evidence, never from a number the LLM states; and
every investigation ends at a policy seam that, today, always defers to a human. See
[`01-governed-core.md`](01-governed-core.md) for how each of those is actually built.

## The Seven-Layer Target Architecture

| # | Layer | What it does | Status |
|---|---|---|---|
| 1 | **Sensor / Detection Engineering** | Zeek, auditd, Suricata, OPNsense filterlog — the actual telemetry and detection logic that gives BLIP-AI something to investigate | ✅ Exists — see [Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab) |
| 2 | **Telemetry / SIEM** | Splunk Enterprise ingesting all of the above, queryable via SPL | ✅ Exists — V1.1 (`splunk_connector.py`) |
| 3 | **Typed Tool Layer** | The only interface the agent has to the outside world — schema-validated, risk-tagged, guardrailed, fully audit-logged | ✅ Exists — `blip_core/tools/` |
| 4 | **Deterministic Reasoning Layer** | Confidence scoring, MITRE mapping, and (stubbed) policy — pure Python, no LLM involved | ✅ Exists — `blip_core/deterministic/` |
| 5 | **Agentic LLM Layer** | The governed tool-calling loop: propose a tool call, execute it, repeat until conclusion or iteration cap | ✅ Exists (v1) — `blip_core/llm/`, `blip_core/loop.py` |
| 6 | **Verdict & Audit Layer** | The structured record every investigation produces — tool transcript, tagged evidence, confidence breakdown, MITRE mapping, narrative, policy decision | ✅ Exists — `blip_core/verdict/`, `blip_core/audit/` |
| 7 | **Policy & Response Layer** | The real policy engine (confidence + evidence quality + reversibility + asset criticality + blast radius) and actual response execution — OPNsense blocking, TheHive case creation, SOAR workflows | ⏳ Planned — today's `deterministic/policy.py` always returns `RECOMMEND`; nothing executes anything |

Layers 1–2 are the existing, proven V1.1 foundation and the homelab's detection
engineering work. Layers 3–6 are what `blip_core` adds. Layer 7 is intentionally the
last thing to build — see [`01-governed-core.md`](01-governed-core.md#the-policy-seam)
for why the policy seam exists now as a stub rather than being skipped until it's real.

## Relationship to the Detection Engineering Homelab

BLIP-AI's investigative reasoning is only as good as the evidence it's reasoning over.
That evidence — the Splunk detections, the auditd rules, the Zeek/Suricata signatures,
the attack simulations that validated each one — is built and documented separately in
**[Taylor-Cybersecurity-Homelab](https://github.com/tjglass814/Taylor-Cybersecurity-Homelab)**.
Think of that repo as Layer 1 (and the detection logic behind Layer 2): it's where new
telemetry sources and detection rules get engineered and proven before BLIP-AI's tool
layer ever gets a typed wrapper around them.

## Stage Docs

| Doc | Covers |
|---|---|
| [`01-governed-core.md`](01-governed-core.md) | The first `blip_core` build stage: the four architectural bones, the corroboration-based confidence model, the module layout, test coverage, and known limitations |

More stage docs land here as `blip_core` grows — the LLM agent gaining richer tool
access, the policy engine becoming real, response execution being added under Layer 7.
