"""
BLIP-AI Core — Audit Log
========================
Append-only JSONL record of every tool call the investigation agent
makes. This is the raw material for a verdict's tool_transcript and,
eventually, the "why?" explainability view — nothing here is summarized
or dropped. Written under its own directory so it never collides with
the reports/ directory used by the V1.1 narrative reports.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class AuditLog:

    def __init__(self, log_dir: str = "blip_core_logs"):
        self.log_dir = log_dir

    def _log_path(self) -> str:
        os.makedirs(self.log_dir, exist_ok=True)
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        return os.path.join(self.log_dir, f"tool_calls_{date_str}.jsonl")

    def record(
        self,
        seq: int,
        tool_name: str,
        input: Dict[str, Any],
        output: Optional[Dict[str, Any]],
        risk_level: str,
        llm_rationale: str,
        timestamp: str,
        error: Optional[str] = None,
    ) -> None:
        entry = {
            "seq": seq,
            "tool_name": tool_name,
            "input": input,
            "output": output,
            "risk_level": risk_level,
            "llm_rationale": llm_rationale,
            "timestamp": timestamp,
            "error": error,
        }
        with open(self._log_path(), "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
