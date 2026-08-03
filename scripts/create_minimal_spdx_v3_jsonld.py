#!/usr/bin/env python3
"""
Create a minimal SPDX 3.0 JSON-LD document directly.

This script generates a valid SPDX 3.0 JSON-LD document by building
the structure directly without relying on potentially problematic
spdx-tools model imports.
"""

from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import sys
from uuid import uuid4


def build_minimal_spdx3_jsonld(
    name: str,
    namespace: str,
    creator_name: str,
) -> dict:
    """Build a minimal SPDX 3.0 JSON-LD document structure."""

    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"
    creator_id = f"{namespace}#creator-{uuid4()}"
    bundle_id = f"{namespace}#bundle-{uuid4()}"

    # Build SPDX 3.0 JSON-LD structure
    document = {
        "@context": "https://spdx.github.io/spdx-spec/v3.0/model/jsonld/context.json",
        "@graph": [
            {
                "@type": "Bundle",
                "spdxId": bundle_id,
                "creationInfo": {
                    "specVersion": "3.0.0",
                    "created": created,
                    "createdBy": [creator_id],
                    "profile": ["core"],
                },
                "name": name,
            }
        ],
    }

    return document


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a minimal SPDX 3.0 JSON-LD document."
    )
    parser.add_argument(
        "--name",
        default="Minimal SPDX 3.0 Document",
        help="Document name"
    )
    parser.add_argument(
        "--namespace",
        default="https://example.org/spdx3/minimal-doc-1",
        help="Unique document namespace URI",
    )
    parser.add_argument(
        "--creator",
        default="License Facade Service",
        help="Creator tool name"
    )
    parser.add_argument(
        "--out",
        default="minimal.spdx3.jsonld",
        help="Output SPDX 3.0 JSON-LD file path"
    )
    args = parser.parse_args()

    print(f"Creating SPDX 3.0 document...")
    print(f"  Name: {args.name}")
    print(f"  Namespace: {args.namespace}")
    print(f"  Creator: {args.creator}")

    # Build the document
    document = build_minimal_spdx3_jsonld(
        name=args.name,
        namespace=args.namespace,
        creator_name=args.creator,
    )

    # Prepare output path
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write to file
    try:
        with open(out_path, "w") as f:
            spdx = json.dump(document, f, indent=2)
            print(spdx)
            print(f"  Written document: {out_path}")

        print(f"\n✓ Wrote SPDX 3.0 JSON-LD document to: {out_path}")
        print("✓ SPDX 3.0 document created successfully")
        print(f"  Schema: https://spdx.github.io/spdx-spec/v3.0/")
        print(f"  Format: JSON-LD")
    except Exception as e:
        print(f"✗ Failed to write document: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

