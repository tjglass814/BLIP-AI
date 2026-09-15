"""
BLIP-AI Core — Investigation Agent
===================================
The agentic tool-calling loop. The LLM's only powers are: read the
transcript so far, choose one tool to call next, and — via a special
conclude_investigation tool — end the investigation with tagged
evidence and a narrative. It never sees a shell, never supplies a
confidence number, and never calls more than max_iterations tools.

InvestigationAgent is pure loop logic against an LLMClient protocol, so
it is fully unit-testable with a scripted fake client — no network
call, no Splunk, no Claude API key required. AnthropicLLMClient is the
concrete implementation used in production, wrapping the anthropic SDK
the same way claude_analyst.py does (same model family, same
config/.env credential loading), and is not itself unit-tested here for
the same reason claude_analyst.py isn't: it needs a live API key.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Protocol

import anthropic
from dotenv import load_dotenv

from blip_core.deterministic.evidence_tags import EVIDENCE_TAGS
from blip_core.llm.prompts import SYSTEM_PROMPT
from blip_core.tools.base import Tool
from blip_core.tools.registry import ToolRegistry
from blip_core.verdict.schema import EVIDENCE_SOURCES, ToolCall

load_dotenv("config/.env")

CONCLUDE_TOOL_NAME = "conclude_investigation"


class AgentProtocolError(Exception):
    """Raised when the LLM client returns something the agent loop can't act on."""


def _identity(**kwargs) -> Dict[str, Any]:
    return kwargs


CONCLUDE_TOOL = Tool(
    name=CONCLUDE_TOOL_NAME,
    description=(
        "Call this when you have enough evidence to conclude the investigation, or "
        "once you are out of useful tool calls. Provide the evidence you found, each "
        "item tagged with a canonical source and tag — never a confidence number, "
        "that is computed deterministically — plus your reasoning narrative."
    ),
    input_schema={
        "type": "object",
        "required": ["evidence", "reasoning_narrative"],
        "properties": {
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["source", "tag", "detail"],
                    "properties": {
                        "source": {"type": "string", "enum": list(EVIDENCE_SOURCES)},
                        "tag": {"type": "string", "enum": list(EVIDENCE_TAGS.keys())},
                        "detail": {"type": "object"},
                    },
                },
            },
            "reasoning_narrative": {"type": "string"},
        },
    },
    output_schema={
        "type": "object",
        "required": ["evidence", "reasoning_narrative"],
        "properties": {
            "evidence": {"type": "array"},
            "reasoning_narrative": {"type": "string"},
        },
    },
    risk_level="read_only",
    handler=_identity,
)


@dataclass
class ToolCallStep:
    """One turn's decision: call this tool, with this input, for this reason."""

    tool_name: str
    tool_input: Dict[str, Any]
    rationale: str


class LLMClient(Protocol):
    def next_step(
        self, alert_name: str, transcript: List[ToolCall], iteration: int, max_iterations: int
    ) -> ToolCallStep:
        ...


@dataclass
class AgentResult:
    status: str  # "CONCLUDED" | "MAX_ITERATIONS_REACHED" | "ERROR"
    iterations_used: int
    transcript: List[ToolCall]
    raw_evidence: List[Dict[str, Any]]
    narrative: str


class InvestigationAgent:
    """
    Runs the governed loop: ask the LLM for the next tool call, execute
    it through the (already guardrailed, already audit-logged)
    ToolRegistry, feed the result back, repeat until
    conclude_investigation succeeds or max_iterations is reached.
    """

    def __init__(self, registry: ToolRegistry, llm_client: LLMClient, max_iterations: int):
        self.registry = registry
        self.llm_client = llm_client
        self.max_iterations = max_iterations

    def run(self, alert_name: str) -> AgentResult:
        transcript: List[ToolCall] = []

        for iteration in range(1, self.max_iterations + 1):
            try:
                step = self.llm_client.next_step(
                    alert_name=alert_name,
                    transcript=transcript,
                    iteration=iteration,
                    max_iterations=self.max_iterations,
                )
            except Exception as exc:
                return AgentResult(
                    status="ERROR",
                    iterations_used=iteration - 1,
                    transcript=transcript,
                    raw_evidence=[],
                    narrative=f"LLM call failed on iteration {iteration}: {exc}",
                )

            if not isinstance(step, ToolCallStep):
                return AgentResult(
                    status="ERROR",
                    iterations_used=iteration - 1,
                    transcript=transcript,
                    raw_evidence=[],
                    narrative=f"LLM client returned an unusable step type: {type(step)!r}",
                )

            timestamp = datetime.now(timezone.utc).isoformat()
            try:
                output = self.registry.call(
                    step.tool_name, seq=iteration, llm_rationale=step.rationale, **step.tool_input
                )
                call_failed = False
            except Exception as exc:
                output = {"error": str(exc)}
                call_failed = True

            try:
                risk_level = self.registry.get(step.tool_name).risk_level
            except KeyError:
                risk_level = "unknown"

            transcript.append(
                ToolCall(
                    seq=iteration,
                    tool_name=step.tool_name,
                    input=step.tool_input,
                    output_summary=output,
                    risk_level=risk_level,
                    llm_rationale=step.rationale,
                    timestamp=timestamp,
                )
            )

            if step.tool_name == CONCLUDE_TOOL_NAME and not call_failed:
                return AgentResult(
                    status="CONCLUDED",
                    iterations_used=iteration,
                    transcript=transcript,
                    raw_evidence=output["evidence"],
                    narrative=output["reasoning_narrative"],
                )

        return AgentResult(
            status="MAX_ITERATIONS_REACHED",
            iterations_used=self.max_iterations,
            transcript=transcript,
            raw_evidence=[],
            narrative=(
                "Investigation stopped after reaching the maximum iteration count "
                "without a successful conclude_investigation call."
            ),
        )


def tool_to_anthropic_schema(tool: Tool) -> Dict[str, Any]:
    """Anthropic's tool spec shape is already what our Tool.input_schema uses."""
    return {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}


class AnthropicLLMClient:
    """
    Production LLMClient backed by Claude's tool-use API. Rebuilds the
    conversation from the transcript on every call rather than holding
    persistent state, so a fresh AnthropicLLMClient mid-investigation
    (e.g. after a process restart) would behave identically.
    """

    def __init__(self, tools: List[Tool], model: str = "claude-sonnet-4-6"):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model = model
        self.anthropic_tools = [tool_to_anthropic_schema(t) for t in tools]

    def next_step(
        self, alert_name: str, transcript: List[ToolCall], iteration: int, max_iterations: int
    ) -> ToolCallStep:
        messages = self._build_messages(alert_name, transcript, iteration, max_iterations)
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=self.anthropic_tools,
            messages=messages,
        )
        return self._parse_response(response)

    def _build_messages(
        self, alert_name: str, transcript: List[ToolCall], iteration: int, max_iterations: int
    ) -> List[Dict[str, Any]]:
        messages: List[Dict[str, Any]] = [
            {
                "role": "user",
                "content": (
                    f"Alert: {alert_name}\n"
                    f"Iteration {iteration} of {max_iterations} maximum.\n"
                    "Investigate using the available tools, then call "
                    "conclude_investigation when you have enough evidence."
                ),
            }
        ]
        for call in transcript:
            call_id = f"call_{call.seq}"
            messages.append(
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": call_id, "name": call.tool_name, "input": call.input}
                    ],
                }
            )
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": call_id,
                            "content": json.dumps(call.output_summary, default=str),
                        }
                    ],
                }
            )
        return messages

    def _parse_response(self, response) -> ToolCallStep:
        tool_use_block = next((b for b in response.content if b.type == "tool_use"), None)
        if tool_use_block is None:
            raise AgentProtocolError(
                "Claude did not call a tool this turn — every turn must call exactly one."
            )
        rationale = " ".join(b.text for b in response.content if b.type == "text").strip()
        return ToolCallStep(tool_name=tool_use_block.name, tool_input=tool_use_block.input, rationale=rationale)
