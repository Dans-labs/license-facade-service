#!/usr/bin/env python3
"""
Convert SPDX 2.x documents to SPDX 3.0 format.

This script uses the spdx-tools bump_from_spdx2 module to convert
SPDX 2.x JSON/RDF/Tag-Value documents to SPDX 3.0 JSON-LD format.

Based on: https://github.com/spdx/tools-python/tree/main/src/spdx_tools/spdx3/bump_from_spdx2
"""

from pathlib import Path
import argparse
import sys
import json
from uuid import uuid4
from datetime import datetime, timezone

from spdx_tools.spdx.parser.parse_anything import parse_file as parse_spdx2


def convert_spdx2_to_spdx3_manual(spdx2_doc) -> dict:
    """
    Manually convert SPDX 2.x document to SPDX 3.0 JSON-LD format.

    This is a fallback when bump_from_spdx2 module is not available.
    """

    creation_info = spdx2_doc.creation_info

    # Generate IDs
    doc_id = f"https://spdx.org/spdxdocs/{uuid4()}"
    bundle_id = f"{doc_id}#SPDXRef-DOCUMENT"

    # Build SPDX 3.0 JSON-LD structure
    elements = []

    # Add creation tool/organization as Bundle creator
    creator_id = f"{doc_id}#creator-{uuid4()}"

    # Create document element
    document = {
        "@type": "Bundle",
        "spdxId": bundle_id,
        "creationInfo": {
            "specVersion": "3.0.0",
            "created": datetime.now(timezone.utc).isoformat() + "Z",
            "createdBy": [creator_id],
            "profile": ["core"],
        },
        "name": creation_info.name,
    }

    # Add packages
    element_refs = []
    for pkg in spdx2_doc.packages:
        pkg_id = f"{doc_id}#{pkg.spdx_id}"
        element_refs.append(pkg_id)

        package = {
            "@type": "software_Package",
            "spdxId": pkg_id,
            "name": pkg.name,
            "creationInfo": {
                "specVersion": "3.0.0",
                "created": creation_info.created.isoformat() + "Z" if hasattr(creation_info.created, 'isoformat') else str(creation_info.created),
                "createdBy": [creator_id],
            },
        }

        if pkg.download_location:
            package["downloadLocation"] = str(pkg.download_location)

        elements.append(package)

    # Add files from packages
    for pkg in spdx2_doc.packages:
        if hasattr(pkg, 'files') and pkg.files:
            for file in pkg.files:
                file_id = f"{doc_id}#{file.spdx_id}"
                element_refs.append(file_id)

                file_elem = {
                    "@type": "software_File",
                    "spdxId": file_id,
                    "name": file.name,
                    "creationInfo": {
                        "specVersion": "3.0.0",
                        "created": creation_info.created.isoformat() + "Z" if hasattr(creation_info.created, 'isoformat') else str(creation_info.created),
                        "createdBy": [creator_id],
                    },
                }
                elements.append(file_elem)

    document["element"] = element_refs
    document["rootElement"] = element_refs[:1] if element_refs else []
    elements.insert(0, document)

    # Build JSON-LD structure
    jsonld = {
        "@context": "https://spdx.github.io/spdx-spec/v3.0/model/jsonld/context.json",
        "@graph": elements,
    }

    return jsonld


def convert_spdx2_to_spdx3(input_file: str, output_file: str, verbose: bool = False) -> bool:
    """
    Convert SPDX 2.x document to SPDX 3.0 JSON-LD format.

    Args:
        input_file: Path to SPDX 2.x file (JSON, RDF, or Tag-Value)
        output_file: Path to output SPDX 3.0 JSON-LD file
        verbose: Enable verbose output

    Returns:
        True if conversion successful, False otherwise
    """

    input_path = Path(input_file)
    output_path = Path(output_file)

    # Validate input file exists
    if not input_path.exists():
        print(f"✗ Input file not found: {input_path}")
        return False

    try:

        # Step 1: Parse SPDX 2.x document
        print(f"📖 Parsing SPDX 2.x document from: {input_path}")
        spdx2_document = parse_spdx2(str(input_path))

        if verbose:
            print(f"   ✓ Document: {spdx2_document.creation_info.name}")
            print(f"   ✓ SPDX Version: {spdx2_document.creation_info.spdx_version}")
            print(f"   ✓ Namespace: {spdx2_document.creation_info.document_namespace}")
            print(f"   ✓ Packages: {len(spdx2_document.packages)}")
            # Files may not exist in all SPDX documents
            try:
                files_count = sum(len(pkg.files) if hasattr(pkg, 'files') else 0 for pkg in spdx2_document.packages)
                print(f"   ✓ Files: {files_count}")
            except:
                pass

        # Step 2: Convert to SPDX 3.0
        print(f"\n🔄 Converting SPDX 2.x to SPDX 3.0...")

        # Try official converter first
        try:
            from spdx_tools.spdx3.bump_from_spdx2 import convert_document
            print("   Using official converter...")
            spdx3_payload = convert_document(spdx2_document)
            use_manual = False
        except (ImportError, ModuleNotFoundError, AttributeError):
            print("   Using fallback manual converter...")
            spdx3_payload = convert_spdx2_to_spdx3_manual(spdx2_document)
            use_manual = True

        if verbose:
            if use_manual:
                print(f"   ✓ Elements: {len(spdx3_payload.get('@graph', []))}")
            else:
                print(f"   ✓ SPDX documents: {len(spdx3_payload.spdx_documents)}")
                print(f"   ✓ Elements: {len(spdx3_payload.elements)}")

        # Step 3: Write SPDX 3.0 document
        print(f"\n💾 Writing SPDX 3.0 JSON-LD to: {output_path}")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to file
        with open(output_path, "w") as f:
            if use_manual:
                # Already in JSON-LD dict format
                json.dump(spdx3_payload, f, indent=2)
            else:
                # Try to use spdx-tools writer, fallback to JSON
                try:
                    from spdx_tools.spdx3.writer.write_anything import write_file as write_spdx3
                    write_spdx3(spdx3_payload, str(output_path))
                except (ImportError, ModuleNotFoundError, AttributeError):
                    # Fallback: write as JSON
                    json.dump(spdx3_payload, f, indent=2)

        # Step 4: Validate output file
        if output_path.exists():
            file_size = output_path.stat().st_size
            print(f"   ✓ File size: {file_size:,} bytes")

        print(f"\n✓ Conversion completed successfully!")
        print(f"  Input:  {input_path}")
        print(f"  Output: {output_path}")

        return True

    except FileNotFoundError as e:
        print(f"✗ File not found: {e}")
        return False
    except ValueError as e:
        print(f"✗ Invalid SPDX 2.x file: {e}")
        return False
    except Exception as e:
        print(f"✗ Conversion error: {type(e).__name__}: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert SPDX 2.x documents to SPDX 3.0 JSON-LD format.",
        epilog="""
Examples:
  # Convert JSON file
  python convert_spdx2_to_v3.py input.spdx.json output.spdx3.jsonld
  
  # Convert RDF file
  python convert_spdx2_to_v3.py input.spdx.rdf output.spdx3.jsonld
  
  # Convert Tag-Value file with verbose output
  python convert_spdx2_to_v3.py input.spdx -v output.spdx3.jsonld
  
  # Batch conversion
  for file in *.spdx.json; do
    python convert_spdx2_to_v3.py "$file" "${file%.json}.spdx3.jsonld"
  done
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "input",
        help="Input SPDX 2.x file (JSON, RDF, or Tag-Value format)"
    )
    parser.add_argument(
        "output",
        help="Output SPDX 3.0 JSON-LD file path"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output with detailed conversion info"
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Overwrite output file if it exists"
    )

    args = parser.parse_args()

    # Check if output file exists
    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        print(f"⚠ Output file already exists: {args.output}")
        print(f"Use -f/--force to overwrite")
        sys.exit(1)

    # Convert
    print("=" * 70)
    print("SPDX 2.x to 3.0 Converter")
    print("=" * 70)
    print()

    success = convert_spdx2_to_spdx3(
        input_file=args.input,
        output_file=args.output,
        verbose=args.verbose
    )

    print()
    print("=" * 70)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

