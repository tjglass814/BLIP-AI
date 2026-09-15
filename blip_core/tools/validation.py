"""
BLIP-AI Core — Minimal Schema Validation
=========================================
A small, dependency-free JSON-Schema-subset validator used to check
tool inputs and outputs against their declared schemas. Supports the
handful of constructs BLIP-AI tools actually use: object/properties/
required, string, number, integer, boolean, array, and enum.
"""

from typing import Any, Dict, List

_TYPE_MAP = {
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
}


def validate(data: Any, schema: Dict[str, Any], path: str = "$") -> List[str]:
    """Return a list of human-readable validation errors (empty if valid)."""
    errors: List[str] = []

    expected_type = schema.get("type")
    if expected_type:
        py_type = _TYPE_MAP.get(expected_type)
        if py_type and not isinstance(data, py_type):
            errors.append(f"{path}: expected {expected_type}, got {type(data).__name__}")
            return errors  # further checks on a wrong-typed value would be meaningless

    if expected_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for field_name in required:
            if field_name not in data:
                errors.append(f"{path}: missing required field '{field_name}'")
        for field_name, value in data.items():
            field_schema = properties.get(field_name)
            if field_schema:
                errors.extend(validate(value, field_schema, path=f"{path}.{field_name}"))

    if expected_type == "array":
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(data):
                errors.extend(validate(item, item_schema, path=f"{path}[{i}]"))

    enum = schema.get("enum")
    if enum is not None and data not in enum:
        errors.append(f"{path}: value '{data}' not in allowed enum {enum}")

    return errors
