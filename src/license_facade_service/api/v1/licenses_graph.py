"""
Example: RDF API Endpoints Integration

This file demonstrates how to integrate RDF output into the License Facade Service API.
Add these endpoints to src/license_facade_service/api/v1/licenses.py
"""

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from typing import Optional
import logging

from src.license_facade_service.utils.rdf_transformer import (
    json_to_rdf,
    json_list_to_rdf
)

# This would be added to the existing licenses.py router
router = APIRouter()


@router.get("/licenses/{id}/rdf")
async def get_license_rdf(
    id: str,
    format: str = Query(
        default="turtle",
        description="RDF format: turtle, xml, json-ld, nt, n3"
    )
):
    """
    Get a license in RDF format.

    Supported formats:
    - turtle: Turtle format (.ttl)
    - xml: RDF/XML format (.rdf)
    - json-ld: JSON-LD format (.jsonld)
    - nt: N-Triples format (.nt)
    - n3: Notation3 format (.n3)
    """
    try:
        # Get license data using existing function
        from src.license_facade_service.api.v1.licenses import (
            get_license,
            generate_license_uri
        )

        # Search by UUID in URI or by licenseId
        license_info = await get_license(id)
        if not license_info:
            raise HTTPException(status_code=404, detail=f"License not found: {id}")

        # Convert to RDF
        rdf_output = json_to_rdf(license_info, format=format)

        # Set appropriate content type
        content_types = {
            "turtle": "text/turtle; charset=utf-8",
            "ttl": "text/turtle; charset=utf-8",
            "xml": "application/rdf+xml; charset=utf-8",
            "rdf": "application/rdf+xml; charset=utf-8",
            "json-ld": "application/ld+json; charset=utf-8",
            "jsonld": "application/ld+json; charset=utf-8",
            "nt": "application/n-triples; charset=utf-8",
            "ntriples": "application/n-triples; charset=utf-8",
            "n3": "text/n3; charset=utf-8"
        }

        content_type = content_types.get(format.lower(), "text/turtle; charset=utf-8")

        return Response(
            content=rdf_output,
            media_type=content_type,
            headers={
                "Content-Disposition": f"inline; filename=license_{id}.{format}",
                "Cache-Control": "public, max-age=3600"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error generating RDF for license {id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate RDF: {str(e)}"
        )


@router.get("/licenses.rdf")
async def get_all_licenses_rdf(
    format: str = Query(
        default="turtle",
        description="RDF format: turtle, xml, json-ld, nt, n3"
    ),
    limit: Optional[int] = Query(
        default=None,
        description="Limit number of licenses returned"
    )
):
    """
    Get all licenses in RDF format.

    Returns a complete RDF graph containing all license metadata.
    """
    try:
        # Get all licenses using existing function
        from src.license_facade_service.api.v1.licenses import get_all_licenses_with_details

        licenses_list = await get_all_licenses_with_details()

        # Apply limit if specified
        if limit and limit > 0:
            licenses_list = licenses_list[:limit]

        # Convert to RDF
        rdf_output = json_list_to_rdf(licenses_list, format=format)

        # Set appropriate content type
        content_types = {
            "turtle": "text/turtle; charset=utf-8",
            "ttl": "text/turtle; charset=utf-8",
            "xml": "application/rdf+xml; charset=utf-8",
            "rdf": "application/rdf+xml; charset=utf-8",
            "json-ld": "application/ld+json; charset=utf-8",
            "jsonld": "application/ld+json; charset=utf-8",
            "nt": "application/n-triples; charset=utf-8",
            "ntriples": "application/n-triples; charset=utf-8",
            "n3": "text/n3; charset=utf-8"
        }

        content_type = content_types.get(format.lower(), "text/turtle; charset=utf-8")

        return Response(
            content=rdf_output,
            media_type=content_type,
            headers={
                "Content-Disposition": f"inline; filename=licenses.{format}",
                "Cache-Control": "public, max-age=3600"
            }
        )

    except Exception as e:
        logging.error(f"Error generating RDF for all licenses: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate RDF: {str(e)}"
        )


@router.get("/licenses/{id}/turtle")
async def get_license_turtle(id: str):
    """Convenience endpoint for Turtle format."""
    return await get_license_rdf(id, format="turtle")


@router.get("/licenses/{id}/rdfxml")
async def get_license_rdfxml(id: str):
    """Convenience endpoint for RDF/XML format."""
    return await get_license_rdf(id, format="xml")


@router.get("/licenses/{id}/jsonld")
async def get_license_jsonld(id: str):
    """Convenience endpoint for JSON-LD format."""
    return await get_license_rdf(id, format="json-ld")


# Additional utility endpoint for content negotiation
@router.get("/licenses/{id}")
async def get_license_content_negotiation(
    id: str,
    request: Request
):
    """
    Get license with content negotiation support.

    Returns format based on Accept header:
    - text/turtle -> Turtle RDF
    - application/rdf+xml -> RDF/XML
    - application/ld+json -> JSON-LD
    - application/json -> JSON (default)
    """
    accept_header = request.headers.get("accept", "application/json")

    # Map Accept headers to formats
    if "text/turtle" in accept_header or "application/turtle" in accept_header:
        return await get_license_rdf(id, format="turtle")
    elif "application/rdf+xml" in accept_header:
        return await get_license_rdf(id, format="xml")
    elif "application/ld+json" in accept_header:
        return await get_license_rdf(id, format="json-ld")
    elif "application/n-triples" in accept_header:
        return await get_license_rdf(id, format="nt")
    else:
        # Default to existing JSON endpoint
        from src.license_facade_service.api.v1.licenses import get_license
        return await get_license(id)


# Example usage documentation
"""
Example API calls:

1. Get license in Turtle format:
   GET /api/v1/licenses/AFL-1.1/rdf?format=turtle
   GET /api/v1/licenses/AFL-1.1/turtle

2. Get license in RDF/XML format:
   GET /api/v1/licenses/AFL-1.1/rdf?format=xml
   GET /api/v1/licenses/AFL-1.1/rdfxml

3. Get license in JSON-LD format:
   GET /api/v1/licenses/AFL-1.1/rdf?format=json-ld
   GET /api/v1/licenses/AFL-1.1/jsonld

4. Get all licenses in RDF (Turtle):
   GET /api/v1/licenses.rdf
   GET /api/v1/licenses.rdf?format=turtle

5. Get limited licenses in RDF:
   GET /api/v1/licenses.rdf?limit=10

6. Content negotiation (using Accept header):
   curl -H "Accept: text/turtle" https://lfs.labs.dansdemo.nl/api/v1/licenses/AFL-1.1
   curl -H "Accept: application/ld+json" https://lfs.labs.dansdemo.nl/api/v1/licenses/AFL-1.1
"""

