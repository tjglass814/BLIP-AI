import types

import pytest

from blip_core.audit.log import AuditLog
from blip_core.llm.agent import (
    CONCLUDE_TOOL,
    CONCLUDE_TOOL_NAME,
    AnthropicLLMClient,
    InvestigationAgent,
    ToolCallStep,
)
from blip_core.tools.base import Tool
from blip_core.tools.registry import ToolRegistry


def make_lookup_tool():
    return Tool(
        name="lookup",
        description="A fake read-only lookup tool for testing.",
        input_schema={
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "required": ["found"],
            "properties": {"found": {"type": "boolean"}},
        },
        risk_level="read_only",
        handler=lambda value: {"found": value == "known"},
    )


@pytest.fixture
def registry(tmp_path):
    reg = ToolRegistry(audit_log=AuditLog(log_dir=str(tmp_path)))
    reg.register(make_lookup_tool())
    reg.register(CONCLUDE_TOOL)
    return reg


class ScriptedLLMClient:
    """Returns a fixed queue of ToolCallSteps regardless of transcript content."""

    def __init__(self, steps):
        self._steps = list(steps)
        self.calls = []

    def next_step(self, alert_name, transcript, iteration, max_iterations):
        self.calls.append((alert_name, iteration, len(transcript)))
        return self._steps.pop(0)


class RaisingLLMClient:
    def next_step(self, alert_name, transcript, iteration, max_iterations):
        raise RuntimeError("simulated LLM outage")


class WrongTypeLLMClient:
    def next_step(self, alert_name, transcript, iteration, max_iterations):
        return {"not": "a ToolCallStep"}


def conclude_step(evidence=None, narrative="Investigation complete."):
    return ToolCallStep(
        tool_name=CONCLUDE_TOOL_NAME,
        tool_input={"evidence": evidence or [], "reasoning_narrative": narrative},
        rationale="Enough evidence gathered.",
    )


def lookup_step(value="known"):
    return ToolCallStep(tool_name="lookup", tool_input={"value": value}, rationale="Checking a lead.")


def test_single_tool_call_then_conclude(registry):
    evidence = [{"source": "auditd_host", "tag": "ssh_brute_force", "detail": {"count": 42}}]
    client = ScriptedLLMClient([lookup_step(), conclude_step(evidence, "Brute force confirmed.")])
    agent = InvestigationAgent(registry=registry, llm_client=client, max_iterations=5)

    result = agent.run("Test Alert")

    assert result.status == "CONCLUDED"
    assert result.iterations_used == 2
    assert result.raw_evidence == evidence
    assert result.narrative == "Brute force confirmed."
    assert len(result.transcript) == 2
    assert result.transcript[0].tool_name == "lookup"
    assert result.transcript[1].tool_name == CONCLUDE_TOOL_NAME


def test_max_iterations_reached_without_conclude(registry):
    client = ScriptedLLMClient([lookup_step() for _ in range(3)])
    agent = InvestigationAgent(registry=registry, llm_client=client, max_iterations=3)

    result = agent.run("Test Alert")

    assert result.status == "MAX_ITERATIONS_REACHED"
    assert result.iterations_used == 3
    assert len(result.transcript) == 3
    assert result.raw_evidence == []


def test_llm_exception_produces_error_status(registry):
    agent = InvestigationAgent(registry=registry, llm_client=RaisingLLMClient(), max_iterations=5)
    result = agent.run("Test Alert")

    assert result.status == "ERROR"
    assert result.iterations_used == 0
    assert "simulated LLM outage" in result.narrative
    assert result.transcript == []


def test_llm_client_returning_wrong_type_produces_error_status(registry):
    agent = InvestigationAgent(registry=registry, llm_client=WrongTypeLLMClient(), max_iterations=5)
    result = agent.run("Test Alert")

    assert result.status == "ERROR"
    assert "unusable step type" in result.narrative


def test_failed_tool_call_is_recorded_and_loop_continues(registry):
    bad_step = ToolCallStep(tool_name="does_not_exist", tool_input={}, rationale="oops")
    client = ScriptedLLMClient([bad_step, conclude_step()])
    agent = InvestigationAgent(registry=registry, llm_client=client, max_iterations=5)

    result = agent.run("Test Alert")

    assert result.status == "CONCLUDED"
    assert len(result.transcript) == 2
    assert "error" in result.transcript[0].output_summary
    assert result.transcript[0].risk_level == "unknown"


def test_conclude_with_invalid_tag_is_rejected_and_loop_continues(registry):
    bad_conclude = ToolCallStep(
        tool_name=CONCLUDE_TOOL_NAME,
        tool_input={"evidence": [{"source": "not_a_source", "tag": "ssh_brute_force", "detail": {}}],
                    "reasoning_narrative": "x"},
        rationale="premature",
    )
    client = ScriptedLLMClient([bad_conclude, conclude_step()])
    agent = InvestigationAgent(registry=registry, llm_client=client, max_iterations=5)

    result = agent.run("Test Alert")

    assert result.status == "CONCLUDED"
    assert len(result.transcript) == 2
    assert "error" in result.transcript[0].output_summary  # the invalid conclude attempt failed
    assert result.raw_evidence == []  # the second, valid conclude call had empty evidence


def test_conclude_tool_input_schema_rejects_unknown_source_and_tag():
    from blip_core.tools.validation import validate

    bad = {
        "evidence": [{"source": "made_up", "tag": "made_up_tag", "detail": {}}],
        "reasoning_narrative": "x",
    }
    errors = validate(bad, CONCLUDE_TOOL.input_schema)
    assert errors  # schema enum rejects unknown source/tag


def test_conclude_with_stray_confidence_field_is_rejected_and_loop_continues(registry):
    smuggled_confidence = ToolCallStep(
        tool_name=CONCLUDE_TOOL_NAME,
        tool_input={
            "evidence": [
                {"source": "auditd_host", "tag": "ssh_brute_force", "detail": {}, "confidence": 0.95}
            ],
            "reasoning_narrative": "x",
        },
        rationale="trying to sneak a confidence score past the evidence contract",
    )
    client = ScriptedLLMClient([smuggled_confidence, conclude_step()])
    agent = InvestigationAgent(registry=registry, llm_client=client, max_iterations=5)

    result = agent.run("Test Alert")

    assert result.status == "CONCLUDED"
    assert len(result.transcript) == 2
    assert "error" in result.transcript[0].output_summary
    assert "confidence" in result.transcript[0].output_summary["error"]
    assert result.raw_evidence == []  # the smuggled attempt failed; only the clean conclude succeeded


def test_conclude_with_mismatched_source_and_tag_is_rejected_and_loop_continues(registry):
    """
    ssh_brute_force is only allowed from auditd_host — attributing it to
    opnsense_network instead must be rejected rather than accepted,
    since it would falsely inflate confidence's corroboration bonus.
    """
    mismatched = ToolCallStep(
        tool_name=CONCLUDE_TOOL_NAME,
        tool_input={
            "evidence": [{"source": "opnsense_network", "tag": "ssh_brute_force", "detail": {}}],
            "reasoning_narrative": "x",
        },
        rationale="mismatched tag/source pairing",
    )
    client = ScriptedLLMClient([mismatched, conclude_step()])
    agent = InvestigationAgent(registry=registry, llm_client=client, max_iterations=5)

    result = agent.run("Test Alert")

    assert result.status == "CONCLUDED"
    assert len(result.transcript) == 2
    assert "error" in result.transcript[0].output_summary
    assert "ssh_brute_force" in result.transcript[0].output_summary["error"]
    assert result.raw_evidence == []  # the mismatched attempt failed; only the clean conclude succeeded


def test_guardrail_violation_is_caught_recorded_and_loop_continues(monkeypatch, tmp_path):
    """
    A real GuardrailViolation, raised inside the real splunk_search tool, must
    be caught by the agent loop rather than crashing the investigation.
    """
    from blip_core.tools import splunk_tools

    def unreachable_connector():
        raise AssertionError("guardrail should have rejected the query before reaching Splunk")

    monkeypatch.setattr(splunk_tools, "_get_connector", unreachable_connector)

    guardrail_registry = ToolRegistry(audit_log=AuditLog(log_dir=str(tmp_path)))
    guardrail_registry.register(splunk_tools.SPLUNK_SEARCH)
    guardrail_registry.register(CONCLUDE_TOOL)

    destructive_step = ToolCallStep(
        tool_name="splunk_search",
        tool_input={"spl": "search index=main | delete", "earliest": "-1h"},
        rationale="attempting a destructive query",
    )
    client = ScriptedLLMClient([destructive_step, conclude_step()])
    agent = InvestigationAgent(registry=guardrail_registry, llm_client=client, max_iterations=5)

    result = agent.run("Test Alert")

    assert result.status == "CONCLUDED"
    assert result.iterations_used == 2
    assert len(result.transcript) == 2

    rejected_call = result.transcript[0]
    assert rejected_call.tool_name == "splunk_search"
    assert "error" in rejected_call.output_summary
    assert "not on the allowed" in rejected_call.output_summary["error"]
    # tool metadata still resolves correctly even though the call itself failed
    assert rejected_call.risk_level == "read_only"

    assert result.transcript[1].tool_name == CONCLUDE_TOOL_NAME


def test_anthropic_client_forces_a_tool_call_every_turn(monkeypatch):
    """
    tool_choice must require the model to call one of the given tools
    every turn, rather than allowing a plain-text turn that produces no
    tool_use block at all.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = AnthropicLLMClient(tools=[CONCLUDE_TOOL])

    captured = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        block = types.SimpleNamespace(
            type="tool_use",
            id="call_1",
            name=CONCLUDE_TOOL_NAME,
            input={"evidence": [], "reasoning_narrative": "done"},
        )
        return types.SimpleNamespace(content=[block])

    monkeypatch.setattr(client.client.messages, "create", fake_create)

    step = client.next_step(alert_name="Test Alert", transcript=[], iteration=1, max_iterations=3)

    assert captured["tool_choice"] == {"type": "any"}
    assert step.tool_name == CONCLUDE_TOOL_NAME
