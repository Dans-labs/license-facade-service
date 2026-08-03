#!/usr/bin/env python3
from datetime import datetime, timezone
from pathlib import Path
import argparse
import sys

from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    CreationInfo,
    Document,
    Package,
    PackagePurpose,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
)
from spdx_tools.spdx.writer.json.json_writer import write_document_to_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document


def build_minimal_document(
    name: str,
    namespace: str,
    creator_name: str,
    spdx_id: str = "SPDXRef-DOCUMENT",
) -> Document:
    created = datetime.now(timezone.utc).replace(microsecond=0)

    creation_info = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id=spdx_id,
        name=name,
        document_namespace=namespace,
        creators=[Actor(ActorType.TOOL, creator_name)],
        created=created,
        data_license="CC0-1.0",
    )

    # spdx-tools validation requires a DESCRIBES relationship when a package is present.
    package = Package(
        spdx_id="SPDXRef-Package-1",
        name="minimal-package",
        download_location=SpdxNoAssertion(),
        version="0.0.1",
        files_analyzed=False,
        license_concluded=SpdxNoAssertion(),
        license_declared=SpdxNoAssertion(),
        copyright_text=SpdxNoAssertion(),
        primary_package_purpose=PackagePurpose.LIBRARY,
    )

    relationship = Relationship(
        spdx_element_id=spdx_id,
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id=package.spdx_id,
    )

    # Minimal valid document for current spdx-tools validator.
    return Document(
        creation_info=creation_info,
        packages=[package],
        relationships=[relationship],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a minimal SPDX document using spdx-tools.")
    parser.add_argument("--name", default="Minimal SPDX Document", help="Document name")
    parser.add_argument(
        "--namespace",
        default="https://example.org/spdx/minimal-doc-1",
        help="Unique document namespace URI",
    )
    parser.add_argument("--creator", default="License Facade Service", help="Creator tool/person/org")
    parser.add_argument("--out", default="minimal.spdx.json", help="Output SPDX JSON file path")
    args = parser.parse_args()

    doc = build_minimal_document(
        name=args.name,
        namespace=args.namespace,
        creator_name=args.creator,
    )

    # Validate document before writing.
    validation_messages = validate_full_spdx_document(doc)
    if validation_messages:
        print("SPDX validation failed:")
        for msg in validation_messages:
            print(f"- {msg}")
        sys.exit(1)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_document_to_file(document=doc, file_name=str(out_path))

    print(f"Wrote minimal SPDX document to: {out_path}")
    print("SPDX validation passed")


if __name__ == "__main__":
    main()