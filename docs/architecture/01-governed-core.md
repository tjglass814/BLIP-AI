# P0 — The Governed Core

**Status:** ✅ Complete
**Module:** `blip_core/`
**Tests:** 139 passing

This is the foundation of BLIP-AI: an AI investigation engine that can only act
through safe, pre-approved tools, computes its own confidence with deterministic
code, and logs everything it does. Nothing is user-visible yet — this is the
skeleton and nervous system that every later phase attaches to.

---

## What Was Built

```
blip_core/
├── tools/
│   ├── base.py            Tool contract: name, description, in/out schema, risk
│   ├── validation.py      dependency-free JSON-schema validator
│   ├── guardrails.py      reject destructive SPL · enforce 24h range · allowlist
│   ├── registry.py        validates in → runs → validates out → audits every call
│   └── splunk_tools.py    splunk_search, pivot_on_entity (wrap SplunkConnector)
├── deterministic/
│   ├── confidence.py      corroboration-based scoring (see below)
│   ├── mitre.py           evidence tag → ATT&CK technique mapping
│   ├── evidence_tags.py   fixed tag → confidence-weight table + allowed sources
│   └── policy.py          decide(verdict) → PolicyDecision (v1: always RECOMMEND)
├── llm/
│   ├── agent.py           the tool-calling loop (LLM picks tools or concludes)
│   └── prompts.py         system prompts for tool selection + final narrative
├── verdict/
│   └── schema.py          Verdict / ToolCall / EvidenceItem / ConfidenceFactor /
│                          MitreMapping / PolicyDecision
└── audit/
    └── log.py             append-only JSONL, one line per tool call
```

## How an Investigation Flows

```
Alert
  │
  ▼
Investigation Loop  ──►  LLM proposes a tool call
  │                          │
  │                          ▼
  │                     Tool Registry  ──►  guardrail check  ──►  Splunk (read-only)
  │                          │
  │                          ▼
  │                     audit log (every call, success or failure)
  │                          │
  ◄──────────────────────────┘  result fed back to LLM
  │
  │   (loop, max 5 iterations, until the LLM calls conclude_investigation)
  ▼
Evidence collected
  │
  ▼
Deterministic confidence  +  MITRE mapping   (Python, not the LLM)
  │
  ▼
Policy decision  (v1: RECOMMEND)
  │
  ▼
Verdict object  (evidence trail · per-source tags · confidence breakdown · reasoning)
```

The key architectural boundary: **the LLM drives the investigation but never grades
its own work.** It chooses which tools to call and writes the narrative; Python
computes the confidence, maps MITRE techniques, and runs policy. The LLM literally
has no field in which to assert a confidence number.

## The Four Non-Negotiable Properties

1. **Typed tools, not shell access.** The engine can only call defined tools with
   input/output schemas and risk levels. `pivot_on_entity` has no free-text query
   surface at all — it composes pre-approved building blocks. There is no path to
   an arbitrary command.
2. **Deterministic vs. LLM split.** Thresholds, confidence math, MITRE mapping, and
   policy are plain Python. The LLM only interprets, hypothesizes, selects the next
   tool, and writes the narrative.
3. **Structured verdict object.** Every investigation returns one object with the
   full tool transcript, per-source evidence tags, a deterministically-computed
   confidence and its breakdown, MITRE techniques, and the reasoning narrative.
   This is the audit record and the seed of the future traceability view.
4. **Policy seam.** A separate policy module returns a decision (v1: always
   RECOMMEND). It exists as its own module from day one so the real policy engine
   grows here without touching the loop.

## How Confidence Works

Confidence is scored by **independent-source corroboration**, not a flat sum. The
same amount of evidence scores higher when it comes from multiple distinct sources:

| Distinct sources | Multiplier |
|---|---|
| 1 | 1.00 |
| 2 | 1.15 |
| 3 | 1.30 |
| 4 | 1.40 |

So `0.4 + 0.4` from one source scores `0.80`; the same `0.4 + 0.4` split across two
independent sources scores `0.92`. Every score emits a breakdown so it can be
traced back to exactly which sources and multiplier produced it.

## Hardening (post security review)

An automated multi-agent code review surfaced real findings, since fixed:

- **Time-range bypass** — the guardrail now inspects the SPL string itself for
  embedded `earliest=`/`latest=` modifiers, so the 24h cap cannot be sidestepped.
- **Denylist → allowlist** — the read-only check now allowlists ~30 known-safe SPL
  commands and fails closed on anything unrecognized.
- **Source enforcement** — a tag can only be attributed to a source on its allowed
  list, so the corroboration multiplier cannot be inflated by a mismatched pairing.
- **Forced tool use** — the model must call a tool every turn (no dead-end
  plain-text turns that discard evidence).
- **Isolated audit writes** — logging failures no longer mask a successful result,
  and unknown-tool attempts are still logged.

## Design Decisions

> **Fresh core alongside V1.1.**
> I chose to build blip_core as a new package rather than refactor the existing
> investigation_engine.py. The old engine works and I didn't want to break it while
> experimenting — keeping V1.1 intact gave me a working fallback the whole way
> through. More importantly, the old code carried assumptions from its
> additive-scoring, single-pass design, and I didn't want to fight those while
> building a governed agentic architecture. A clean core let the new design's
> structure (typed tools, deterministic/LLM split) show up in the file layout
> instead of being bolted onto something that wasn't shaped for it.

> **Corroboration-based confidence.**
> I deliberately made evidence from multiple independent sources score higher than
> the same amount of evidence from one source. The reasoning is how a real analyst
> thinks: one sensor firing five times could be noise or a misconfiguration, but
> three different vantage points — network behavior, host activity, and a known
> signature — all pointing at the same entity is much harder to explain away. Flat
> additive scoring treats those as equal; they aren't. The multiplier encodes that
> an attack corroborated across telemetry types is closer to certain than a single
> loud source.

> **Guardrails-first build order.**
> I built and tested the safety layer — the SPL guardrails, the audit log, the
> typed-tool boundary — before building the investigation loop that uses them. The
> reason is where this platform is headed: eventually the engine will be able to
> take real defensive actions, including touching the firewall. A system like that
> can't have its safety proven as an afterthought. Building guardrails first, with
> their own passing tests, means the loop was never able to run an unbounded or
> destructive query even once — the safety existed before the capability did.

## Known Limitations

See [../../blip_core/KNOWN_ISSUES.md](../../blip_core/KNOWN_ISSUES.md). Most notably: when an
investigation hits the max-iteration cap without a clean conclusion, accumulated
evidence is currently discarded and the verdict scores as informational — a long,
complex investigation could therefore under-score. A future fix will return a
partial verdict from evidence gathered so far.
