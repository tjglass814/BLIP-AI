"""
BLIP-AI Core — Tool Registry
============================
The only path through which the investigation agent can act. Every
call is schema-validated on input and output and written to the audit
log — success or failure — so the agent never has an unmediated side
channel to Splunk or anything else.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from blip_core.audit.log import AuditLog
from blip_core.tools.base import Tool
from blip_core.tools.validation import validate

logger = logging.getLogger(__name__)


class SchemaValidationError(Exception):
    """Raised when tool input or output fails schema validation."""


class ToolRegistry:

    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._tools: Dict[str, Tool] = {}
        self.audit_log = audit_log or AuditLog()

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"No such tool: '{name}'")
        return self._tools[name]

    def list_tools(self):
        return list(self._tools.values())

    def _safe_record(self, **kwargs: Any) -> None:
        """
        Write one audit-log entry without letting a logging failure (a
        full disk, an unwritable log directory, ...) mask the tool-call
        outcome — success, validation failure, or handler exception —
        that the caller is about to return or raise.
        """
        try:
            self.audit_log.record(**kwargs)
        except Exception:
            logger.exception("Failed to write audit log entry for tool '%s'", kwargs.get("tool_name"))

    def call(self, tool_name: str, seq: int = 0, llm_rationale: str = "", **kwargs) -> Dict[str, Any]:
        """
        Validate input, invoke the tool's handler, validate output, and log
        the full call — input, output, and rationale — regardless of outcome,
        including a call to a tool name that isn't registered at all.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            tool = self.get(tool_name)
        except KeyError as exc:
            self._safe_record(
                seq=seq, tool_name=tool_name, input=kwargs, output=None,
                risk_level="unknown", llm_rationale=llm_rationale,
                timestamp=timestamp, error=f"unknown tool: {exc}",
            )
            raise

        input_errors = validate(kwargs, tool.input_schema)
        if input_errors:
            self._safe_record(
                seq=seq, tool_name=tool_name, input=kwargs, output=None,
                risk_level=tool.risk_level, llm_rationale=llm_rationale,
                timestamp=timestamp, error=f"input validation failed: {input_errors}",
            )
            raise SchemaValidationError(f"Invalid input for '{tool_name}': {input_errors}")

        try:
            output = tool.handler(**kwargs)
        except Exception as exc:
            self._safe_record(
                seq=seq, tool_name=tool_name, input=kwargs, output=None,
                risk_level=tool.risk_level, llm_rationale=llm_rationale,
                timestamp=timestamp, error=str(exc),
            )
            raise

        output_errors = validate(output, tool.output_schema)
        if output_errors:
            self._safe_record(
                seq=seq, tool_name=tool_name, input=kwargs, output=output,
                risk_level=tool.risk_level, llm_rationale=llm_rationale,
                timestamp=timestamp, error=f"output validation failed: {output_errors}",
            )
            raise SchemaValidationError(f"Invalid output from '{tool_name}': {output_errors}")

        self._safe_record(
            seq=seq, tool_name=tool_name, input=kwargs, output=output,
            risk_level=tool.risk_level, llm_rationale=llm_rationale,
            timestamp=timestamp, error=None,
        )
        return output
