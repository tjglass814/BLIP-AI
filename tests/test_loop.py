from blip_core.audit.log import AuditLog
from blip_core.deterministic.confidence import verdict_tier
from blip_core.llm.agent import CONCLUDE_TOOL_NAME, ToolCallStep
from blip_core.loop import default_tool_registry, investigate
from blip_core.tools.splunk_tools import PIVOT_ON_ENTITY, SPLUNK_SEARCH


class ScriptedLLMClient:
    def __init__(self, steps):
        self._steps = list(steps)

    def next_step(self, alert_name, transcript, iteration, max_iterations):
        return self._steps.pop(0)


def test_default_tool_registry_has_the_expected_tools():
    registry = default_tool_registry()
    names = {tool.name for tool in registry.list_tools()}
    assert names == {SPLUNK_SEARCH.name, PIVOT_ON_ENTITY.name, CONCLUDE_TOOL_NAME}


def test_investigate_builds_a_full_verdict_from_llm_conclusion(tmp_path):
    registry = default_tool_registry(audit_log=AuditLog(log_dir=str(tmp_path)))
    evidence = [
        {"source": "auditd_host", "tag": "privilege_escalation_confirmed", "detail": {"auid": "1000"}},
        {"source": "zeek_behavioral", "tag": "network_reconnaissance", "detail": {"src_ip": "10.10.10.132"}},
    ]
    client = ScriptedLLMClient(
        [
            ToolCallStep(
                tool_name=CONCLUDE_TOOL_NAME,
                tool_input={"evidence": evidence, "reasoning_narrative": "Escalation and recon confirmed."},
                rationale="Sufficient evidence.",
            )
        ]
    )

    verdict = investigate("Privilege Escalation Confirmed", registry=registry, llm_client=client, max_iterations=5)

    assert verdict.status == "CONCLUDED"
    assert verdict.alert_name == "Privilege Escalation Confirmed"
    assert len(verdict.evidence) == 2
    assert verdict.llm_reasoning_narrative == "Escalation and recon confirmed."

    # 0.35 + 0.20 = 0.55 base, two independent sources -> x1.15 = 0.6325 -> 0.63
    assert verdict.confidence_score == 0.63
    assert verdict_tier(verdict.confidence_score) == "MEDIUM — Suspicious activity detected"

    mitre_ids = {m.id for m in verdict.mitre_techniques}
    assert "T1548" in mitre_ids
    assert "T1046" in mitre_ids

    assert verdict.policy_decision.decision == "RECOMMEND"
    assert len(verdict.tool_transcript) == 1


def test_investigate_handles_max_iterations_reached(tmp_path):
    registry = default_tool_registry(audit_log=AuditLog(log_dir=str(tmp_path)))
    from blip_core.tools.base import Tool

    def handler(spl, earliest="-1h", latest="now"):
        return {"results": [], "count": 0}

    # Replace splunk_search's handler so the fake registry never touches real Splunk.
    fake_search = Tool(
        name=SPLUNK_SEARCH.name,
        description=SPLUNK_SEARCH.description,
        input_schema=SPLUNK_SEARCH.input_schema,
        output_schema=SPLUNK_SEARCH.output_schema,
        risk_level=SPLUNK_SEARCH.risk_level,
        handler=handler,
    )
    registry._tools[fake_search.name] = fake_search

    client = ScriptedLLMClient(
        [
            ToolCallStep(tool_name="splunk_search", tool_input={"spl": "search index=main", "earliest": "-1h"}, rationale="looking")
            for _ in range(2)
        ]
    )

    verdict = investigate("Quiet Alert", registry=registry, llm_client=client, max_iterations=2)

    assert verdict.status == "MAX_ITERATIONS_REACHED"
    assert verdict.evidence == []
    assert verdict.confidence_score == 0.0
    assert verdict.policy_decision.decision == "RECOMMEND"
