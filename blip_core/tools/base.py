"""
BLIP-AI Core — Tool Contract
============================
Defines the typed tool interface used by the investigation agent.
The LLM never executes raw commands — it can only invoke tools that
satisfy this contract, each with declared input/output schemas and a
risk level, so every side-effecting action is inspectable ahead of time.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict

RISK_LEVELS = ("read_only", "low", "medium", "high")


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    risk_level: str
    handler: Callable[..., Dict[str, Any]]

    def __post_init__(self):
        if self.risk_level not in RISK_LEVELS:
            raise ValueError(
                f"Unknown risk_level '{self.risk_level}' for tool '{self.name}' "
                f"— must be one of {RISK_LEVELS}"
            )
