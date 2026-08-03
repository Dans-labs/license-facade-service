"""
Test script for RDF Transformer

This script demonstrates how to use the RDF transformer to convert
license JSON data to various RDF formats.
"""

import json
from pathlib import Path
from src.license_facade_service.utils.rdf_transformer import (
    RDFTransformer,
    json_to_rdf,
    json_list_to_rdf
)


def test_single_license_transformation():
    """Test transforming a single license to RDF."""
    print("=" * 80)
    print("Test 1: Transform single license to RDF")
    print("=" * 80)

    # Load a sample license
    license_file = Path("resources/data/licenses/AFL-1.1.json")

    if not license_file.exists():
        print(f"Error: License file not found: {license_file}")
        return

    with open(license_file, 'r') as f:
        license_data = json.load(f)

    # Transform to different formats
    formats = ["turtle", "xml", "json-ld", "nt"]

    for fmt in formats:
        print(f"\n--- Format: {fmt.upper()} ---")
        try:
            rdf_output = json_to_rdf(license_data, format=fmt)

            # Print first 500 characters
            print(rdf_output[:500])
            if len(rdf_output) > 500:
                print(f"... (truncated, total length: {len(rdf_output)} characters)")

            # Save to file
            output_file = Path(f"test_output_afl_1_1.{fmt}")
            with open(output_file, 'w') as f:
                f.write(rdf_output)
            print(f"Saved to: {output_file}")

        except Exception as e:
            print(f"Error converting to {fmt}: {e}")


def test_licenses_list_transformation():
    """Test transforming a list of licenses to RDF."""
    print("\n" + "=" * 80)
    print("Test 2: Transform licenses list to RDF")
    print("=" * 80)

    # Load licenses list cache
    licenses_list_file = Path("resources/data/licenses/licenses_list.json")

    if not licenses_list_file.exists():
        print(f"Error: Licenses list file not found: {licenses_list_file}")
        return

    with open(licenses_list_file, 'r') as f:
        licenses_data = json.load(f)

    licenses = licenses_data.get("licenses", [])

    # Take first 10 licenses for testing
    sample_licenses = licenses[:10]

    print(f"\nTransforming {len(sample_licenses)} licenses to Turtle format...")

    try:
        rdf_output = json_list_to_rdf(sample_licenses, format="turtle")

        # Print first 1000 characters
        print(rdf_output[:1000])
        if len(rdf_output) > 1000:
            print(f"... (truncated, total length: {len(rdf_output)} characters)")

        # Save to file
        output_file = Path("test_output_licenses_list.ttl")
        with open(output_file, 'w') as f:
            f.write(rdf_output)
        print(f"\nSaved to: {output_file}")

    except Exception as e:
        print(f"Error: {e}")


def test_transformer_class():
    """Test using the RDFTransformer class directly."""
    print("\n" + "=" * 80)
    print("Test 3: Using RDFTransformer class directly")
    print("=" * 80)

    # Load a sample license
    license_file = Path("resources/data/licenses/0BSD.json")

    if not license_file.exists():
        print(f"Error: License file not found: {license_file}")
        return

    with open(license_file, 'r') as f:
        license_data = json.load(f)

    # Create transformer and transform
    transformer = RDFTransformer()
    transformer.transform_license(license_data)

    # Save to multiple formats
    formats = {
        "turtle": "ttl",
        "xml": "rdf",
        "json-ld": "jsonld"
    }

    for fmt, ext in formats.items():
        output_file = f"test_output_0bsd.{ext}"
        try:
            transformer.save_to_file(output_file, format=fmt)
            print(f"Saved {fmt} format to: {output_file}")
        except Exception as e:
            print(f"Error saving {fmt}: {e}")


def test_all_licenses_in_directory():
    """Test transforming all licenses in the directory."""
    print("\n" + "=" * 80)
    print("Test 4: Transform all licenses in directory")
    print("=" * 80)

    licenses_dir = Path("resources/data/licenses")

    if not licenses_dir.exists():
        print(f"Error: Licenses directory not found: {licenses_dir}")
        return

    # Get all JSON files (excluding licenses_list.json and version.json)
    license_files = [
        f for f in licenses_dir.glob("*.json")
        if f.name not in ["licenses_list.json", "version.json"]
    ]

    print(f"\nFound {len(license_files)} license files")
    print(f"Processing first 5 licenses...")

    transformer = RDFTransformer()
    output_dir = Path("test_rdf_output")
    output_dir.mkdir(exist_ok=True)

    for i, license_file in enumerate(license_files[:5], 1):
        try:
            with open(license_file, 'r') as f:
                license_data = json.load(f)

            transformer.reset_graph()
            transformer.transform_license(license_data)

            # Save as turtle
            output_file = output_dir / f"{license_file.stem}.ttl"
            transformer.save_to_file(str(output_file), format="turtle")

            print(f"{i}. Transformed {license_file.name} -> {output_file.name}")

        except Exception as e:
            print(f"{i}. Error processing {license_file.name}: {e}")

    print(f"\nRDF files saved to: {output_dir}")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("RDF Transformer Test Suite")
    print("=" * 80)

    try:
        test_single_license_transformation()
        test_licenses_list_transformation()
        test_transformer_class()
        test_all_licenses_in_directory()

        print("\n" + "=" * 80)
        print("All tests completed!")
        print("=" * 80 + "\n")

    except Exception as e:
        print(f"\nTest suite error: {e}")
        import traceback
        traceback.print_exc()

