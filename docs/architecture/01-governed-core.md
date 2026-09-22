# Stage 1 — The Governed Core

> The first `blip_core` build stage: a typed-tool agent loop with deterministic
> confidence and MITRE mapping, a structured verdict object, and a policy seam that
> (for now) never auto-executes anything.

This stage answers one question: can an LLM drive an investigation — choosing what to
check next, forming its own hypotheses — without ever being trusted with a shell, a
number it invented, or an unlogged action? The four architectural bones below are the
answer.

---

## The Four Architectural Bones

### 1. Typed tools, not shell

The agent's only interface to the outside world is `blip_core/tools/`: a `Tool`
contract (name, description, input schema, output schema, risk level, handler),
enforced by a `ToolRegistry` that validates every call's input and output against its
schema and writes it to an append-only audit log before returning. `splunk_search` and
`pivot_on_entity` wrap the existing `SplunkConnector` — the agent never sees raw shell,
raw SPL execution, or the connector directly.

**Why:** a shell is a blank check. A typed tool is a promise about exactly what can
happen and what the result will look like — which is what makes the next three bones
possible at all.

### 2. Deterministic vs. LLM split

`blip_core/deterministic/` (confidence math, MITRE mapping, the policy stub) is plain
Python with no model calls. `blip_core/llm/` (the agent loop, the system prompt) is the
only place a Claude call happens. The LLM's job is narrow: read the transcript, pick a
tool, tag what it found, write a narrative. It never computes a score and never decides
what a piece of evidence maps to in MITRE ATT&CK.

**Why:** confidence scoring and technique mapping are things you want to be able to
audit, unit test, and reason about without a model in the loop — and things you want to
give exactly the same answer on the same input, every time.

### 3. Structured verdict object

Every investigation returns one `Verdict` (`blip_core/verdict/schema.py`): the full
tool-call transcript with each call's rationale, evidence tagged by source
(`zeek_behavioral` / `auditd_host` / `suricata_signature` / `opnsense_network`), a
deterministic confidence score with its factor-by-factor breakdown, MITRE technique
mappings, the LLM's narrative, and the policy decision. Nothing in the verdict is free
text standing on its own — every claim traces back to a specific evidence item or tool
call.

**Why:** this is the audit record and the seed of a future "why did BLIP-AI conclude
this?" explainability view. A verdict that can't be traced back to its evidence isn't
usable in a real incident.

### 4. The policy seam

`blip_core/deterministic/policy.py` exports one function, `decide(verdict)`, which in
v1 always returns `RECOMMEND` — BLIP-AI never auto-executes anything yet. It's its own
module, not an inline check, because the real policy engine (confidence + evidence
quality + reversibility + asset criticality + blast radius, from Layer 7 of the target
architecture) grows into this exact function later without touching the agent loop or
the confidence math around it.

**Why:** building the seam now, even trivial, means "should BLIP-AI act on this" stays
a single, isolated decision point instead of getting scattered across the codebase once
it stops being trivial.

---

## How Confidence Works: Independent-Source Corroboration

`deterministic/confidence.py` does not sum evidence weights flatly. It scores by how
many *distinct* telemetry sources corroborate the finding:

1. Group evidence by source, sum each source's weight, cap the total at `1.0` (the
   `base`).
2. Apply a corroboration multiplier keyed on the number of distinct sources involved:

   | Distinct sources | Multiplier |
   |---|---|
   | 1 | 1.00 |
   | 2 | 1.15 |
   | 3 | 1.30 |
   | 4 (all defined sources) | 1.40 |

3. `final_score = min(base × multiplier, 1.0)`.

So the same total evidence weight scores differently depending on how it's
distributed: 0.4 + 0.4 from **one** source (`auditd_host`) scores **0.80**; the same
0.4 + 0.4 split across **two** sources (`auditd_host`, `zeek_behavioral`) scores
**0.92**. That's deliberate — two independent detection technologies agreeing is
stronger evidence than one sensor firing twice, because a single sensor can be wrong,
misconfigured, or evaded in a way that two unrelated ones agreeing can't easily be.

Verdict tier cutoffs (0.90 / 0.70 / 0.50 / 0.30 → CRITICAL / HIGH / MEDIUM / LOW /
INFORMATIONAL) are ported unchanged from V1.1's `investigation_engine.py`.

### Why the LLM never sets its own confidence

There is no confidence field anywhere in the LLM's output contract. When the agent
calls `conclude_investigation`, it can only supply `evidence` (each item: a
`source`, a `tag` from a fixed vocabulary, and a free-form `detail` blob) and a
`reasoning_narrative` — the tool's schema has no number for the LLM to fill in, and
`additionalProperties: false` on both the top-level call and each evidence item means a
stray field (say, a smuggled `"confidence": 0.95`) is actively rejected, not silently
ignored.

The numeric weight behind every evidence tag lives in
`deterministic/evidence_tags.py::EVIDENCE_TAGS` — a fixed table Python owns. The LLM
picks *which* tag applies to what it found (that's the "interpret evidence" job); the
weight that tag is worth is looked up from this table, never taken from the model. Four
of its tags carry the exact weights V1.1's `investigation_engine.py` already used, for
continuity; the rest were added for MITRE mapping and follow the same convention.

This is the same principle as the deterministic/LLM split, applied to the one place an
LLM would most plausibly try to sneak a number past it.

---

## Module Layout

```
blip_core/
├── __init__.py
├── config.py                    # MAX_ITERATIONS, MAX_QUERY_HOURS
├── KNOWN_ISSUES.md               # honestly-tracked gaps — see below
├── loop.py                       # investigate(alert_name) -> Verdict, top-level orchestrator
├── audit/
│   ├── __init__.py
│   └── log.py                    # append-only JSONL log of every tool call
├── deterministic/
│   ├── __init__.py
│   ├── confidence.py              # independent-source corroboration scoring + verdict tiers
│   ├── evidence_tags.py            # tag -> confidence weight, the LLM's fixed vocabulary
│   ├── mitre.py                     # evidence tag -> MITRE technique mapping
│   └── policy.py                     # decide(verdict) -> PolicyDecision (v1: always RECOMMEND)
├── llm/
│   ├── __init__.py
│   ├── agent.py                      # InvestigationAgent loop, conclude_investigation tool, AnthropicLLMClient
│   └── prompts.py                     # system prompt for the investigative loop
├── tools/
│   ├── __init__.py
│   ├── base.py                        # the Tool contract
│   ├── guardrails.py                   # read-only SPL enforcement, 24h max lookback
│   ├── registry.py                      # ToolRegistry — validates + logs every call
│   ├── splunk_tools.py                   # splunk_search, pivot_on_entity (wrap SplunkConnector)
│   └── validation.py                      # minimal JSON-Schema-subset validator
└── verdict/
    ├── __init__.py
    └── schema.py                          # Verdict and its nested dataclasses
```

## Test Coverage

106 tests across 11 files, all pure — no live Splunk connection, no live Claude API
call, anywhere in the suite:

| File | Tests | Proves |
|---|---|---|
| `test_mitre.py` | 23 | Evidence tag → MITRE technique mapping, status merging (CONFIRMED beats SUSPECTED), unmapped tags raise rather than silently dropping, the mapped technique set matches exactly what the playbooks declare |
| `test_confidence.py` | 18 | The corroboration multiplier table, that multi-source evidence outscores same-total single-source evidence, capping behavior at both the raw-total and post-multiplier stages, and the ported V1.1 verdict tier cutoffs |
| `test_guardrails.py` | 17 | Read-only SPL enforcement (every disallowed command), the 24h max lookback, relative-time-only parsing |
| `test_agent_loop.py` | 9 | The agent's control flow: tool-call-then-conclude, hitting `max_iterations`, LLM exceptions and malformed responses degrading to `ERROR` cleanly, a failed tool call not killing the loop, an invalid `conclude_investigation` call (bad tag, smuggled confidence field) being rejected and retried, and a *real* `GuardrailViolation` being caught and recorded without crashing the investigation |
| `test_evidence_tags.py` | 8 | The evidence tag vocabulary matches `mitre.py`'s exactly, and the four V1.1-ported weights are correct |
| `test_verdict_schema.py` | 7 | Enum validation on every `Verdict` sub-object, and that `to_dict()` round-trips nested dataclasses cleanly |
| `test_splunk_tools.py` | 7 | Guardrails run *before* the (fake) Splunk connector is ever reached, for both destructive SPL and oversized ranges |
| `test_tool_registry.py` | 6 | Input/output schema validation, audit logging on success and failure, duplicate registration and unknown-tool errors |
| `test_validation.py` | 5 | The `additionalProperties` strictness feature — permissive by default, strict opt-in, independent per nesting level |
| `test_policy.py` | 3 | `decide()` always returns `RECOMMEND` regardless of confidence, in v1 |
| `test_loop.py` | 3 | The default tool registry's contents, and two full `investigate()` runs — one concluding with confidence math and MITRE mapping checked against exact expected numbers, one hitting `MAX_ITERATIONS_REACHED` |

## Known Limitations

Full detail: [`../../blip_core/KNOWN_ISSUES.md`](../../blip_core/KNOWN_ISSUES.md).

The one worth calling out here: when an investigation hits `max_iterations` without a
successful `conclude_investigation` call, the resulting verdict discards whatever
evidence earlier tool calls turned up and scores `0.0` / INFORMATIONAL — identical to an
alert that genuinely found nothing. A long, evidence-rich investigation that simply ran
out of turns currently looks exactly like a clean one. This is a known, deliberately
deferred gap, not an oversight discovered after the fact — it's documented rather than
fixed because the right fix depends on a design decision (how much to trust tool output
the LLM never explicitly tagged) that hasn't been made yet.

---

## Design Decisions

> **DESIGN DECISION (in my words):** Why build `blip_core` as a fresh package
> alongside the working V1.1 engine instead of modifying `investigation_engine.py` in
> place?
>
> I chose to build blip_core as a new package rather than refactor the existing
> investigation_engine.py. The old engine works and I didn't want to break it while
> experimenting — keeping V1.1 intact gave me a working fallback the whole way through.
> More importantly, the old code carried assumptions from its additive-scoring,
> single-pass design, and I didn't want to fight those while building a governed
> agentic architecture. A clean core let the new design's structure (typed tools,
> deterministic/LLM split) show up in the file layout instead of being bolted onto
> something that wasn't shaped for it.

> **DESIGN DECISION (in my words):** Why score confidence by independent-source
> corroboration instead of the flat additive sum V1.1 used?
>
> I deliberately made evidence from multiple independent sources score higher than the
> same amount of evidence from one source. The reasoning is how a real analyst thinks:
> one sensor firing five times could be noise or a misconfiguration, but three
> different vantage points — network behavior, host activity, and a known signature —
> all pointing at the same entity is much harder to explain away. Flat additive scoring
> treats those as equal; they aren't. The multiplier (1.0/1.15/1.30/1.40 for 1–4
> sources) encodes that an attack corroborated across telemetry types is closer to
> certain than a single loud source.

> **DESIGN DECISION (in my words):** Why build the typed-tool/guardrail layer
> first, before the LLM agent loop that actually uses it?
>
> I built and tested the safety layer — the SPL guardrails, the audit log, the
> typed-tool boundary — before building the investigation loop that uses them. The
> reason is where this platform is headed: eventually the engine will be able to take
> real defensive actions, including touching the firewall. A system like that can't
> have its safety proven as an afterthought. Building guardrails first, with their own
> passing tests, means the loop was never able to run an unbounded or destructive query
> even once — the safety existed before the capability did.
