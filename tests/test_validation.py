from blip_core.tools.validation import validate


def test_strict_schema_rejects_unrecognized_property():
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "string"}},
        "additionalProperties": False,
    }
    errors = validate({"a": "x", "confidence": 0.9}, schema)
    assert errors
    assert any("confidence" in e for e in errors)


def test_strict_schema_accepts_only_declared_properties():
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "string"}},
        "additionalProperties": False,
    }
    assert validate({"a": "x"}, schema) == []


def test_default_is_permissive_like_json_schema():
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "string"}},
    }
    # no additionalProperties declared -> extra fields are allowed (JSON Schema default)
    assert validate({"a": "x", "extra": 123}, schema) == []


def test_freeform_object_schema_with_no_properties_stays_permissive():
    schema = {"type": "object"}
    assert validate({"anything": "goes", "nested": {"ok": True}}, schema) == []


def test_nested_object_strictness_is_independent_per_level():
    schema = {
        "type": "object",
        "properties": {
            "strict_child": {
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "additionalProperties": False,
            },
            "loose_child": {"type": "object"},
        },
    }
    data = {
        "strict_child": {"x": "ok", "y": "not allowed"},
        "loose_child": {"anything": "goes"},
    }
    errors = validate(data, schema)
    assert len(errors) == 1
    assert "y" in errors[0]
