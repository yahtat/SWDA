"""Minimal JSON-Schema validator (subset) so the PoC has zero third-party dependencies.

Supported keywords: type, enum, required, properties, additionalProperties(false),
items, minItems, maxItems, minimum, maximum, minLength, maxLength, pattern.
In production, swap for the `jsonschema` package - the call sites stay identical.
"""
from __future__ import annotations
import re
from typing import Any

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "integer": int, "number": (int, float), "null": type(None),
}


def validate(instance: Any, schema: dict, path: str = "$") -> list[str]:
    """Return a list of human-readable errors (empty list == valid)."""
    errors: list[str] = []
    t = schema.get("type")
    if t:
        py = _TYPES[t]
        ok = isinstance(instance, py)
        if t in ("integer", "number") and isinstance(instance, bool):
            ok = False
        if not ok:
            return [f"{path}: expected {t}, got {type(instance).__name__}"]
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required field '{req}'")
        if schema.get("additionalProperties") is False:
            for k in instance:
                if k not in props:
                    errors.append(f"{path}: unexpected field '{k}'")
        for k, sub in props.items():
            if k in instance:
                errors.extend(validate(instance[k], sub, f"{path}.{k}"))
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], f"{path}[{i}]"))
    return errors
