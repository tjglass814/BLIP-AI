# BLIP-AI Core — Known Issues

## MAX_ITERATIONS_REACHED discards accumulated evidence

**Where:** `blip_core/llm/agent.py::InvestigationAgent.run()`, consumed by `blip_core/loop.py::investigate()`.

When an investigation hits `max_iterations` without a successful
`conclude_investigation` call, `run()` returns
`AgentResult(status="MAX_ITERATIONS_REACHED", raw_evidence=[], ...)` —
empty, even if earlier tool calls in the transcript surfaced real
findings the model simply never got around to formally submitting via
`conclude_investigation`.

`loop.py` then builds a `Verdict` from that empty evidence list, so
`compute_confidence()` scores it `0.0` and `verdict_tier()` reports
INFORMATIONAL — identical to an investigation that genuinely found
nothing. A long, evidence-rich investigation that merely ran out of
turns is indistinguishable from a clean alert. That's misleading for
anyone consuming the verdict.

**Not fixed tonight — deliberately deferred.** Tracked here so a
MAX_ITERATIONS_REACHED verdict isn't mistaken for "no threat found"
before this is addressed.

**Candidate fix for a later commit:** derive a partial verdict from
whatever evidence exists in the transcript so far, rather than
discarding it outright. This needs a design decision first: how much
trust to put in evidence from a successful tool call the LLM never
explicitly tagged via `conclude_investigation` — tool output isn't
tagged with a `source`/`tag` the way `conclude_investigation`'s
evidence items are, so a deterministic extraction step would need to
either infer tags from which tool was called, or force the agent to
call `conclude_investigation` one final time on its last iteration
with whatever it has (a "you're out of turns, conclude now" prompt on
the final iteration is the simplest version of this).
