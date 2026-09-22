import pytest

from blip_core.audit.log import AuditLog
from blip_core.tools.base import Tool
from blip_core.tools.registry import SchemaValidationError, ToolRegistry


def make_echo_tool():
    return Tool(
        name="echo",
        description="Echoes back the given message.",
        input_schema={
            "type": "object",
            "required": ["message"],
            "properties": {"message": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "required": ["echoed"],
            "properties": {"echoed": {"type": "string"}},
        },
        risk_level="read_only",
        handler=lambda message: {"echoed": message},
    )


@pytest.fixture
def registry(tmp_path):
    return ToolRegistry(audit_log=AuditLog(log_dir=str(tmp_path)))


def test_call_returns_valid_output_and_logs(registry, tmp_path):
    registry.register(make_echo_tool())
    result = registry.call("echo", seq=1, llm_rationale="test", message="hello")
    assert result == {"echoed": "hello"}

    log_files = list(tmp_path.glob("*.jsonl"))
    assert len(log_files) == 1
    assert "hello" in log_files[0].read_text()


def test_call_rejects_missing_required_input(registry):
    registry.register(make_echo_tool())
    with pytest.raises(SchemaValidationError):
        registry.call("echo", seq=1)


def test_call_unknown_tool_raises_keyerror(registry):
    with pytest.raises(KeyError):
        registry.call("does_not_exist", seq=1)


def test_call_unknown_tool_is_still_logged(registry, tmp_path):
    with pytest.raises(KeyError):
        registry.call("does_not_exist", seq=1, llm_rationale="probing", value="x")

    log_files = list(tmp_path.glob("*.jsonl"))
    assert len(log_files) == 1
    log_text = log_files[0].read_text()
    assert "does_not_exist" in log_text
    assert "unknown tool" in log_text


def test_audit_log_write_failure_does_not_mask_a_successful_call(registry, monkeypatch):
    registry.register(make_echo_tool())

    def boom(**kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(registry.audit_log, "record", boom)

    result = registry.call("echo", seq=1, llm_rationale="test", message="hello")
    assert result == {"echoed": "hello"}


def test_audit_log_write_failure_does_not_mask_the_real_handler_exception(registry, monkeypatch):
    def boom(message):
        raise RuntimeError("kaboom")

    tool = make_echo_tool()
    broken_tool = Tool(
        name="broken",
        description="always fails",
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        risk_level="read_only",
        handler=boom,
    )
    registry.register(broken_tool)

    def logging_boom(**kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(registry.audit_log, "record", logging_boom)

    with pytest.raises(RuntimeError, match="kaboom"):
        registry.call("broken", seq=1, message="x")


def test_duplicate_registration_rejected(registry):
    registry.register(make_echo_tool())
    with pytest.raises(ValueError):
        registry.register(make_echo_tool())


def test_handler_exception_is_logged_and_reraised(registry, tmp_path):
    def boom(message):
        raise RuntimeError("kaboom")

    tool = make_echo_tool()
    broken_tool = Tool(
        name="broken",
        description="always fails",
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        risk_level="read_only",
        handler=boom,
    )
    registry.register(broken_tool)
    with pytest.raises(RuntimeError):
        registry.call("broken", seq=1, message="x")

    log_text = list(tmp_path.glob("*.jsonl"))[0].read_text()
    assert "kaboom" in log_text


def test_call_rejects_malformed_output(registry):
    bad_tool = Tool(
        name="bad_output",
        description="returns the wrong shape",
        input_schema={"type": "object", "required": [], "properties": {}},
        output_schema={
            "type": "object",
            "required": ["echoed"],
            "properties": {"echoed": {"type": "string"}},
        },
        risk_level="read_only",
        handler=lambda: {"wrong_field": "oops"},
    )
    registry.register(bad_tool)
    with pytest.raises(SchemaValidationError):
        registry.call("bad_output", seq=1)
