#!/usr/bin/env python
"""Validate rules/default.toml against schemas/sc-rules-v1.json.

The rules file's JSON value (the TOML read as JSON) must validate against the
SC-Rules v1 schema (docs/specs/rules-v1.md). This is a small, stdlib-only
JSON Schema checker: it supports the keywords the schema uses (type,
properties, additionalProperties, required, enum, const, items, $ref/$defs,
minimum, maximum, minLength, pattern, uniqueItems, anyOf, allOf, if/then) and
nothing more, so it stays in the standard library (tomllib, json, re).

Usage:
    python scripts/ci/check-rules-schema.py [rules.toml [schema.json]]

Exit 0 and print OK when valid; exit 1 and print each error otherwise.
"""
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def type_ok(value, t):
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    return True


def resolve(schema, root):
    """Follow a local $ref (#/$defs/name) to its subschema."""
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise ValueError(f"unsupported $ref {ref}")
        node = root
        for part in ref[2:].split("/"):
            node = node[part]
        schema = node
    return schema


def validate(value, schema, root, path, errors):
    schema = resolve(schema, root)

    if "type" in schema:
        t = schema["type"]
        types = t if isinstance(t, list) else [t]
        if not any(type_ok(value, x) for x in types):
            errors.append(f"{path}: expected {t}, got {type(value).__name__}")
            return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum {schema['enum']}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match /{schema['pattern']}/")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} > maximum {schema['maximum']}")

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required '{req}'")
        addl = schema.get("additionalProperties", True)
        for key, sub in value.items():
            if key in props:
                validate(sub, props[key], root, f"{path}.{key}", errors)
            elif addl is False:
                errors.append(f"{path}: unexpected property '{key}'")
            elif isinstance(addl, dict):
                validate(sub, addl, root, f"{path}.{key}", errors)

    if isinstance(value, list):
        if "items" in schema:
            for i, item in enumerate(value):
                validate(item, schema["items"], root, f"{path}[{i}]", errors)
        if schema.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True) for x in value]
            if len(set(seen)) != len(seen):
                errors.append(f"{path}: items are not unique")

    if "anyOf" in schema:
        if not any(
            not sub_errors(value, s, root, path) for s in schema["anyOf"]
        ):
            errors.append(f"{path}: matches none of anyOf")
    for sub in schema.get("allOf", []):
        if "if" in sub:
            if not sub_errors(value, sub["if"], root, path):
                if "then" in sub:
                    validate(value, sub["then"], root, path, errors)
            elif "else" in sub:
                validate(value, sub["else"], root, path, errors)
        else:
            validate(value, sub, root, path, errors)


def sub_errors(value, schema, root, path):
    errs = []
    validate(value, schema, root, path, errs)
    return errs


def main():
    rules_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "rules/default.toml"
    schema_path = (
        Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "schemas/sc-rules-v1.json"
    )
    with open(rules_path, "rb") as f:
        rules = tomllib.load(f)
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    errors = []
    validate(rules, schema, schema, rules_path.name, errors)
    if errors:
        print(f"[check-rules-schema] {rules_path} is not valid SC-Rules v1:")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    print(f"[check-rules-schema] {rules_path.name} is valid SC-Rules v1")


if __name__ == "__main__":
    main()
