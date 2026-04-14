#!/usr/bin/env python3
"""
validate_dataset_schema.py

Validates that a dataset matches the exact schema expected by experiment.py
Run BEFORE any expensive LLM operations.
"""

import json
import sys


def validate_unit(unit, index):
    errors = []

    # 1. Check unit.id exists
    if not unit.get("id"):
        errors.append(f"Unit {index}: missing 'id'")

    # 2. Check unit.code structure (experiment.py lines 186-196)
    code_field = unit.get("code", {})
    if not isinstance(code_field, dict):
        errors.append(f"Unit {index}: 'code' must be dict, got {type(code_field)}")
        return errors

    # 3. Check primary_code exists and is non-empty
    primary_code = code_field.get("primary_code", "")
    if not primary_code:
        errors.append(f"Unit {index}: 'code.primary_code' is empty or missing")

    # 4. Check primary_origin structure
    primary_origin = code_field.get("primary_origin", {})
    if not isinstance(primary_origin, dict):
        errors.append(f"Unit {index}: 'code.primary_origin' must be dict")
        return errors

    # 5. CRITICAL: Check deps_inlined flag (formerly "enhanced")
    # Accept either "deps_inlined" (new) or "enhanced" (legacy) for backward compat
    deps_inlined_key = "deps_inlined" if "deps_inlined" in primary_origin else "enhanced"
    if deps_inlined_key not in primary_origin:
        errors.append(f"Unit {index}: MISSING 'code.primary_origin.deps_inlined'")
    elif not isinstance(primary_origin.get(deps_inlined_key), bool):
        errors.append(f"Unit {index}: 'code.primary_origin.deps_inlined' must be bool")

    # 6. CRITICAL: Check files_included (experiment.py line 192)
    if "files_included" not in primary_origin:
        errors.append(f"Unit {index}: MISSING 'code.primary_origin.files_included'")
    elif not isinstance(primary_origin.get("files_included"), list):
        errors.append(f"Unit {index}: 'code.primary_origin.files_included' must be list")

    # 7. If deps_inlined=true, files_included must have entries
    if primary_origin.get(deps_inlined_key) and not primary_origin.get("files_included"):
        errors.append(f"Unit {index}: deps_inlined=true but files_included is empty")

    # 8. Check file boundaries in primary_code when deps_inlined with multiple files
    if primary_origin.get(deps_inlined_key) and len(primary_origin.get("files_included", [])) > 1:
        if "// ========== File Boundary ==========" not in primary_code:
            errors.append(f"Unit {index}: enhanced with multiple files but no file boundaries")

    return errors


def validate_dataset(path):
    with open(path) as f:
        data = json.load(f)

    all_errors = []
    units = data.get("units", [])

    deps_inlined_count = 0
    for i, unit in enumerate(units):
        errors = validate_unit(unit, i)
        all_errors.extend(errors)

        # Count units with dependencies inlined
        code_field = unit.get("code", {})
        if isinstance(code_field, dict):
            primary_origin = code_field.get("primary_origin", {})
            if primary_origin.get("deps_inlined", primary_origin.get("enhanced")):
                deps_inlined_count += 1

    return all_errors, len(units), deps_inlined_count


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python validate_dataset_schema.py <dataset.json>")
        sys.exit(1)

    errors, total, deps_inlined = validate_dataset(sys.argv[1])

    print(f"Dataset: {sys.argv[1]}")
    print(f"Total units: {total}")
    print(f"Units with deps inlined: {deps_inlined}")
    print()

    if errors:
        print(f"FAILED: {len(errors)} errors:\n")
        for e in errors[:20]:  # Show first 20
            print(f"  - {e}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more errors")
        sys.exit(1)
    else:
        print("PASSED: All units match OpenAnt schema")
        sys.exit(0)
