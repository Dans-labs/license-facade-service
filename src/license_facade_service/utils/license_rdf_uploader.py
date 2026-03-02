"""
License RDF Uploader

This module handles transforming license JSON data to RDF and uploading
to Apache Jena Fuseki.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import json

from src.license_facade_service.utils.rdf_transformer import RDFTransformer
from src.license_facade_service.infra.fuseki_client import FusekiClient


async def upload_licenses_to_fuseki(
    fuseki_client: FusekiClient,
    licenses_list: List[Dict[str, Any]],
    batch_size: int = 50,
    clear_existing: bool = False
) -> Dict[str, Any]:
    """
    Transform licenses to RDF and upload to Fuseki.

    Args:
        fuseki_client: Fuseki client instance
        licenses_list: List of license dictionaries
        batch_size: Number of licenses to upload per batch
        clear_existing: Whether to clear existing data before upload

    Returns:
        Dictionary with upload statistics
    """
    stats = {
        "total_licenses": len(licenses_list),
        "uploaded": 0,
        "failed": 0,
        "batches": 0,
        "errors": []
    }

    try:
        # Clear existing data if requested
        if clear_existing:
            logging.info("Clearing existing data in Fuseki...")
            if await fuseki_client.clear_dataset():
                logging.info("Existing data cleared")
            else:
                logging.warning("Failed to clear existing data, continuing anyway")

        # Create transformer
        transformer = RDFTransformer()

        # Upload in batches
        total_batches = (len(licenses_list) + batch_size - 1) // batch_size

        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(licenses_list))
            batch = licenses_list[start_idx:end_idx]

            logging.info(
                f"Processing batch {batch_num + 1}/{total_batches} "
                f"(licenses {start_idx + 1}-{end_idx})"
            )

            # Transform batch to RDF
            transformer.reset_graph()
            transformer.transform_licenses_list(batch)

            # Upload to Fuseki
            success = await fuseki_client.upload_graph(
                transformer.graph,
                format="turtle"
            )

            if success:
                stats["uploaded"] += len(batch)
                stats["batches"] += 1
                logging.info(
                    f"Batch {batch_num + 1} uploaded successfully "
                    f"({len(batch)} licenses)"
                )
            else:
                stats["failed"] += len(batch)
                error_msg = f"Failed to upload batch {batch_num + 1}"
                stats["errors"].append(error_msg)
                logging.error(error_msg)

        # Get final count from Fuseki
        license_count = await fuseki_client.get_license_count()
        if license_count is not None:
            logging.info(f"Total licenses in Fuseki: {license_count}")
            stats["fuseki_license_count"] = license_count

        triple_count = await fuseki_client.count_triples()
        if triple_count is not None:
            logging.info(f"Total triples in Fuseki: {triple_count}")
            stats["fuseki_triple_count"] = triple_count

    except Exception as e:
        error_msg = f"Error uploading licenses to Fuseki: {e}"
        logging.error(error_msg)
        stats["errors"].append(error_msg)

    return stats


async def upload_all_cached_licenses(
    fuseki_client: FusekiClient,
    cache_dir: Path,
    clear_existing: bool = False
) -> Dict[str, Any]:
    """
    Upload all cached licenses from disk to Fuseki.

    Args:
        fuseki_client: Fuseki client instance
        cache_dir: Directory containing cached license files
        clear_existing: Whether to clear existing data before upload

    Returns:
        Dictionary with upload statistics
    """
    try:
        # Load licenses list
        licenses_list_file = cache_dir / "licenses_list.json"

        if not licenses_list_file.exists():
            logging.error(f"Licenses list not found: {licenses_list_file}")
            return {
                "total_licenses": 0,
                "uploaded": 0,
                "failed": 0,
                "errors": ["Licenses list file not found"]
            }

        with open(licenses_list_file, 'r') as f:
            data = json.load(f)
            licenses_list = data.get("licenses", [])

        logging.info(f"Found {len(licenses_list)} licenses in cache")

        # Load detailed license data
        detailed_licenses = []
        for license_info in licenses_list:
            license_id = license_info.get("licenseId")
            if not license_id:
                continue

            license_file = cache_dir / f"{license_id}.json"
            if license_file.exists():
                try:
                    with open(license_file, 'r') as f:
                        detailed_license = json.load(f)
                        detailed_licenses.append(detailed_license)
                except Exception as e:
                    logging.warning(f"Failed to load {license_id}: {e}")
            else:
                # Use basic info from licenses list
                detailed_licenses.append(license_info)

        logging.info(f"Loaded {len(detailed_licenses)} detailed licenses")

        # Upload to Fuseki
        return await upload_licenses_to_fuseki(
            fuseki_client,
            detailed_licenses,
            clear_existing=clear_existing
        )

    except Exception as e:
        error_msg = f"Error loading cached licenses: {e}"
        logging.error(error_msg)
        return {
            "total_licenses": 0,
            "uploaded": 0,
            "failed": 0,
            "errors": [error_msg]
        }


async def initialize_fuseki_with_licenses(
    fuseki_url: Optional[str] = None,
    dataset: str = "licenses",
    username: Optional[str] = None,
    password: Optional[str] = None,
    cache_dir: Optional[Path] = None,
    clear_existing: bool = False
) -> Dict[str, Any]:
    """
    Initialize Fuseki with license data.

    This is the main function to be called from application startup.

    Args:
        fuseki_url: Base URL of Fuseki server
        dataset: Dataset name
        username: Fuseki admin username
        password: Fuseki admin password
        cache_dir: Directory containing cached licenses
        clear_existing: Whether to clear existing data

    Returns:
        Dictionary with initialization results
    """
    result = {
        "success": False,
        "fuseki_available": False,
        "dataset_created": False,
        "upload_stats": None,
        "errors": []
    }

    try:
        # Create Fuseki client with authentication
        fuseki_client = FusekiClient(
            fuseki_url=fuseki_url,
            dataset=dataset,
            username=username,
            password=password
        )

        # Check Fuseki connection
        logging.info("Checking Fuseki connection...")
        if not await fuseki_client.check_connection():
            error_msg = "Fuseki server is not accessible"
            logging.warning(error_msg)
            result["errors"].append(error_msg)
            return result

        result["fuseki_available"] = True
        logging.info("✓ Fuseki server is accessible")

        # Check/create dataset
        logging.info(f"Checking dataset '{dataset}'...")
        if not await fuseki_client.dataset_exists():
            logging.info(f"Creating dataset '{dataset}'...")
            if not await fuseki_client.create_dataset():
                error_msg = f"Failed to create dataset '{dataset}'"
                logging.error(error_msg)
                result["errors"].append(error_msg)
                return result

        result["dataset_created"] = True
        logging.info(f"✓ Dataset '{dataset}' is ready")

        # Determine cache directory
        if cache_dir is None:
            import os
            base_dir = Path(os.getenv("BASE_DIR", os.getcwd()))
            cache_dir = base_dir / "resources" / "data" / "licenses"

        # Upload licenses
        logging.info("Starting license upload to Fuseki...")
        upload_stats = await upload_all_cached_licenses(
            fuseki_client,
            cache_dir,
            clear_existing=clear_existing
        )

        result["upload_stats"] = upload_stats
        result["success"] = upload_stats["uploaded"] > 0

        # Log summary
        logging.info("=" * 80)
        logging.info("Fuseki Initialization Summary:")
        logging.info(f"  Fuseki URL: {fuseki_url or 'http://localhost:3030'}")
        logging.info(f"  Dataset: {dataset}")
        logging.info(f"  Total licenses: {upload_stats['total_licenses']}")
        logging.info(f"  Uploaded: {upload_stats['uploaded']}")
        logging.info(f"  Failed: {upload_stats['failed']}")
        logging.info(f"  Batches: {upload_stats['batches']}")
        if "fuseki_license_count" in upload_stats:
            logging.info(f"  Licenses in Fuseki: {upload_stats['fuseki_license_count']}")
        if "fuseki_triple_count" in upload_stats:
            logging.info(f"  Total triples: {upload_stats['fuseki_triple_count']}")
        logging.info("=" * 80)

    except Exception as e:
        error_msg = f"Unexpected error during Fuseki initialization: {e}"
        logging.error(error_msg)
        result["errors"].append(error_msg)

    return result

