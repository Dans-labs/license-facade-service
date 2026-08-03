#!/usr/bin/env python3
"""
Create a minimal SPDX 3.0 document using spdx-tools.

Based on: https://github.com/spdx/tools-python?tab=readme-ov-file#quickstart-to-spdx-30
"""

from datetime import datetime, timezone
from pathlib import Path
import argparse
import sys
import json
from uuid import uuid4


def build_minimal_spdx3_document(
    name: str,
    namespace: str,
    creator_name: str,
) -> dict:
    """Build a minimal SPDX 3.0 JSON-LD document matching SPDX license-list style.

    Structure:
    - @context
    - @graph with:
      * CreationInfo node (with @id)
      * SpdxDocument node referencing CreationInfo via creationInfo
    """

    # Timestamps and IDs
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    # Use a blank-node style id for CreationInfo, similar to 0BSD.jsonld
    creation_info_id = "_:creationInfo_0"
    # Use a document IRI under the namespace
    document_spdx_id = f"{namespace.rstrip('/')}_document"

    creation_info_node = {
        "@id": creation_info_id,
        "type": "CreationInfo",
        "specVersion": "3.0.1",
        "createdBy": [f"{namespace.rstrip('/')}/creator"],
        "created": created,
    }

    document_node = {
        "spdxId": document_spdx_id,
        "type": "SpdxDocument",
        "rootElement": [document_spdx_id],
        "name": name,
        "creationInfo": creation_info_id,
    }

    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [creation_info_node, document_node],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a minimal SPDX 3.0 document as JSON-LD."
    )
    parser.add_argument("--name", default="Minimal SPDX 3.0 Document", help="Document name")
    parser.add_argument(
        "--namespace",
        default="https://example.org/spdx3/minimal-doc-1",
        help="Unique document namespace URI",
    )
    parser.add_argument(
        "--creator",
        default="License Facade Service",
        help="Creator tool name (informational only)",
    )
    parser.add_argument(
        "--out",
        default="minimal.spdx3.jsonld",
        help="Output SPDX 3.0 JSON-LD file path",
    )
    args = parser.parse_args()

    print("Creating SPDX 3.0 document...")
    print(f"  Name: {args.name}")
    print(f"  Namespace: {args.namespace}")
    print(f"  Creator: {args.creator}")

    document = build_minimal_spdx3_document(
        name=args.name,
        namespace=args.namespace,
        creator_name=args.creator,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2)

        print("\nSPDX 3.0 JSON-LD document generated.")
        print(f"  -> {out_path}")
        print("You can validate it with:")
        print("  python scripts/validate_spdx_v3.py", out_path)
    except Exception as e:
        print(f"✗ Failed to write document: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

