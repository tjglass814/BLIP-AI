import pytest

from blip_core.tools import splunk_tools
from blip_core.tools.guardrails import GuardrailViolation


class FakeConnector:
    def __init__(self):
        self.run_query_calls = []

    def run_query(self, spl, earliest, latest):
        self.run_query_calls.append((spl, earliest, latest))
        return [{"src_ip": "10.10.10.132", "count": 42}]

    def check_ssh_brute_force(self, hours):
        return [{"src_ip": "10.10.10.132", "count": 42}]

    def check_port_scan(self, src_ip=None, hours=1):
        return [{"src_ip": "10.10.10.132", "unique_ports": 15}]

    def check_recon_campaign(self, hours):
        return [{"src_ip": "10.10.10.132", "scan_windows": 3}]

    def check_privilege_escalation(self, hours):
        return [{"auid": "1000", "processes": ["bash"]}]

    def check_persistence(self, hours):
        return [{"auid": "1000", "mechanisms": ["cron"]}]


@pytest.fixture
def fake_connector(monkeypatch):
    connector = FakeConnector()
    monkeypatch.setattr(splunk_tools, "_get_connector", lambda: connector)
    return connector


def test_splunk_search_runs_valid_query(fake_connector):
    result = splunk_tools._splunk_search("search index=main | stats count", earliest="-4h")
    assert result["count"] == 1
    assert fake_connector.run_query_calls  # guardrails passed, connector was reached


def test_splunk_search_blocks_destructive_spl(fake_connector):
    with pytest.raises(GuardrailViolation):
        splunk_tools._splunk_search("search index=main | delete", earliest="-1h")
    assert not fake_connector.run_query_calls  # never reached the connector


def test_splunk_search_blocks_oversized_range(fake_connector):
    with pytest.raises(GuardrailViolation):
        splunk_tools._splunk_search("search index=main", earliest="-48h")
    assert not fake_connector.run_query_calls


def test_pivot_on_entity_src_ip(fake_connector):
    result = splunk_tools._pivot_on_entity("10.10.10.132", "src_ip")
    assert result["entity"] == "10.10.10.132"
    assert "brute_force" in result and "port_scan" in result and "recon_campaign" in result


def test_pivot_on_entity_auid(fake_connector):
    result = splunk_tools._pivot_on_entity("1000", "auid")
    assert result["entity"] == "1000"
    assert "privilege_escalation" in result and "persistence" in result


def test_pivot_on_entity_rejects_unknown_type(fake_connector):
    with pytest.raises(ValueError):
        splunk_tools._pivot_on_entity("x", "hostname")


def test_tool_definitions_expose_schemas_and_risk_level():
    assert splunk_tools.SPLUNK_SEARCH.risk_level == "read_only"
    assert splunk_tools.PIVOT_ON_ENTITY.risk_level == "read_only"
    assert "spl" in splunk_tools.SPLUNK_SEARCH.input_schema["required"]
