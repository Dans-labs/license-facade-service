#!/usr/bin/env python3
"""Validate an SPDX 3.x JSON-LD document.

Default target:
  /Users/akmi/dev/work/eden/license-facade-service/spdx_downloads/jsonld/0BSD.jsonld

This validator is pragmatic and tailored to SPDX 3.x JSON-LD files
similar to the official SPDX license-list data, e.g. 0BSD.jsonld.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_INPUT = \
    "/Users/akmi/dev/work/eden/license-facade-service/scripts/minimal.spdx3.jsonld"


def _looks_like_spdx3_context(ctx: Any) -> bool:
    """Heuristically check if @context looks like an SPDX 3.x context URL."""
    if isinstance(ctx, str):
        low = ctx.lower()
        return "spdx" in low and ("3." in low or "/v3" in low or "/3/" in low)
    if isinstance(ctx, list):
        return any(_looks_like_spdx3_context(c) for c in ctx)
    return False


def _node_type(node: dict[str, Any]) -> str | None:
    t = node.get("type")
    if isinstance(t, str):
        return t
    t = node.get("@type")
    return t if isinstance(t, str) else None


def _node_id(node: dict[str, Any]) -> str | None:
    sid = node.get("spdxId")
    if isinstance(sid, str):
        return sid
    aid = node.get("@id")
    if isinstance(aid, str):
        return aid
    return None


def _collect_id_map(graph: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for n in graph:
        nid = _node_id(n)
        if isinstance(nid, str):
            by_id[nid] = n
    return by_id


def validate_spdx3_jsonld(doc: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Validate a SPDX 3.x JSON-LD document.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Top-level structure
    if "@context" not in doc:
        errors.append("Missing top-level '@context'.")
    elif not _looks_like_spdx3_context(doc["@context"]):
        warnings.append("Top-level '@context' does not look like an SPDX 3.x context URL.")

    graph = doc.get("@graph")
    if not isinstance(graph, list) or len(graph) == 0:
        errors.append("Missing or empty '@graph' array.")
        return errors, warnings

    by_id = _collect_id_map(graph)

    # Basic node checks
    for i, node in enumerate(graph):
        if not isinstance(node, dict):
            errors.append(f"@graph[{i}] is not an object.")
            continue

        t = _node_type(node)
        if not t:
            errors.append(f"@graph[{i}] missing 'type' or '@type'.")

        if _node_id(node) is None:
            # Not necessarily an error—SPDX CreationInfo in your file uses only @id
            warnings.append(f"@graph[{i}] has neither 'spdxId' nor '@id'.")

    # SpdxDocument presence & checks
    documents = [n for n in graph if _node_type(n) == "SpdxDocument"]
    if not documents:
        errors.append("No 'SpdxDocument' node found in @graph.")
    else:
        for d in documents:
            root = d.get("rootElement")
            if not isinstance(root, list) or len(root) == 0:
                errors.append("SpdxDocument missing non-empty 'rootElement' array.")

            ci_ref = d.get("creationInfo")
            if not isinstance(ci_ref, str):
                errors.append("SpdxDocument 'creationInfo' must be a string reference (e.g. _:creationInfo_0).")
            elif ci_ref not in by_id:
                # In your 0BSD.jsonld, creationInfo is a blank node id (e.g. "_:creationInfo_0"),
                # so it SHOULD appear as an @id in @graph.
                errors.append(
                    f"SpdxDocument creationInfo reference '{ci_ref}' not found as '@id'/'spdxId' in @graph."
                )

    # CreationInfo presence & checks
    creation_infos = [n for n in graph if _node_type(n) == "CreationInfo"]
    if not creation_infos:
        errors.append("No 'CreationInfo' node found in @graph.")
    else:
        for idx, ci in enumerate(creation_infos):
            sv = ci.get("specVersion")
            if not isinstance(sv, str):
                errors.append(f"CreationInfo[{idx}] missing string 'specVersion'.")
            elif not re.match(r"^3\\.\\d+(\\.\\d+)?$", sv):
                warnings.append(f"CreationInfo[{idx}] specVersion '{sv}' is not in 3.x(.x) format.")

            if not isinstance(ci.get("created"), str):
                errors.append(f"CreationInfo[{idx}] missing string 'created'.")

            cb = ci.get("createdBy")
            if not isinstance(cb, list) or len(cb) == 0:
                errors.append(f"CreationInfo[{idx}] missing non-empty list 'createdBy'.")

    # Generic creationInfo reference checks on all nodes
    for i, node in enumerate(graph):
        ci_ref = node.get("creationInfo")
        if ci_ref is None:
            continue
        if not isinstance(ci_ref, str):
            warnings.append(f"@graph[{i}] 'creationInfo' is not a string reference.")
            continue
        if ci_ref not in by_id:
            errors.append(f"@graph[{i}] creationInfo reference '{ci_ref}' not found as ID in @graph.")

    # rootElement references resolution check
    for d in documents:
        for ref in d.get("rootElement", []):
            if isinstance(ref, str) and ref not in by_id:
                warnings.append(
                    f"SpdxDocument rootElement reference '{ref}' not found as 'spdxId'/'@id' in @graph."
                )

    return errors, warnings


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate SPDX 3.x JSON-LD structure.")
    parser.add_argument(
        "input",
        nargs="?",
        default=DEFAULT_INPUT,
        help="Path to SPDX 3 JSON-LD file (default: 0BSD.jsonld)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors (fail on warnings)",
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"ERROR: file not found: {path}")
        sys.exit(2)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: invalid JSON in {path}: {e}")
        sys.exit(2)

    errors, warnings = validate_spdx3_jsonld(data)

    if warnings:
        print("Warnings:")
        for w in warnings:
            print(f"- {w}")

    if errors or (args.strict and warnings):
        print("SPDX v3 validation: FAILED")
        for e in errors:
            print(f"- {e}")
        if args.strict and warnings:
            print("- Strict mode enabled: warnings are treated as errors.")
        sys.exit(1)

    print("SPDX v3 validation: PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()

