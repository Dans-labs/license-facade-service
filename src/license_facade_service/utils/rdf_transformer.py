"""
RDF Transformer for License Data

This module provides functionality to transform SPDX license JSON data
into RDF format using various serializations (Turtle, RDF/XML, JSON-LD, N-Triples).
"""

import logging
from typing import Dict, Any, List, Optional
from rdflib import Graph, Namespace, Literal, URIRef, BNode
from rdflib.namespace import RDF, RDFS, XSD, DCTERMS, FOAF


# Define namespaces
SPDX = Namespace("http://spdx.org/rdf/terms#")
LFS = Namespace("https://lfs.labs.dansdemo.nl/api/v1/licenses/")
CC = Namespace("http://creativecommons.org/ns#")
SCHEMA = Namespace("http://schema.org/")


class RDFTransformer:
    """Transform license JSON data to RDF format."""

    def __init__(self):
        """Initialize the RDF transformer with namespace bindings."""
        self.graph = Graph()
        self._bind_namespaces()

    def _bind_namespaces(self):
        """Bind common namespaces to the graph."""
        self.graph.bind("spdx", SPDX)
        self.graph.bind("lfs", LFS)
        self.graph.bind("cc", CC)
        self.graph.bind("schema", SCHEMA)
        self.graph.bind("dcterms", DCTERMS)
        self.graph.bind("foaf", FOAF)
        self.graph.bind("rdf", RDF)
        self.graph.bind("rdfs", RDFS)

    def reset_graph(self):
        """Reset the graph to empty state."""
        self.graph = Graph()
        self._bind_namespaces()

    def transform_license(self, license_data: Dict[str, Any]) -> Graph:
        """
        Transform a single license JSON object to RDF.

        Args:
            license_data: Dictionary containing license information

        Returns:
            RDFLib Graph object containing the license data
        """
        # Reset graph for new transformation
        self.reset_graph()

        # Get the license URI
        license_uri_str = license_data.get("uri")
        if not license_uri_str:
            logging.warning("License data missing URI field")
            return self.graph

        license_uri = URIRef(license_uri_str)

        # Add type declaration
        self.graph.add((license_uri, RDF.type, SPDX.License))

        # Add license ID
        license_id = license_data.get("licenseId")
        if license_id:
            self.graph.add((license_uri, SPDX.licenseId, Literal(license_id)))
            self.graph.add((license_uri, DCTERMS.identifier, Literal(license_id)))

        # Add license name
        name = license_data.get("name")
        if name:
            self.graph.add((license_uri, SPDX.name, Literal(name)))
            self.graph.add((license_uri, DCTERMS.title, Literal(name)))
            self.graph.add((license_uri, RDFS.label, Literal(name)))

        # Add license text
        license_text = license_data.get("licenseText")
        if license_text:
            self.graph.add((license_uri, SPDX.licenseText, Literal(license_text)))

        # Add standard license template
        std_template = license_data.get("standardLicenseTemplate")
        if std_template:
            self.graph.add((license_uri, SPDX.standardLicenseTemplate, Literal(std_template)))

        # Add standard license header
        std_header = license_data.get("standardLicenseHeader")
        if std_header:
            self.graph.add((license_uri, SPDX.standardLicenseHeader, Literal(std_header)))

        # Add standard license header template
        std_header_template = license_data.get("standardLicenseHeaderTemplate")
        if std_header_template:
            self.graph.add((license_uri, SPDX.standardLicenseHeaderTemplate, Literal(std_header_template)))

        # Add license text HTML
        license_text_html = license_data.get("licenseTextHtml")
        if license_text_html:
            self.graph.add((license_uri, SPDX.licenseTextHtml, Literal(license_text_html)))

        # Add deprecation status
        is_deprecated = license_data.get("isDeprecatedLicenseId", False)
        self.graph.add((license_uri, SPDX.isDeprecatedLicenseId, Literal(is_deprecated, datatype=XSD.boolean)))

        # Add OSI approval status
        is_osi_approved = license_data.get("isOsiApproved", False)
        self.graph.add((license_uri, SPDX.isOsiApproved, Literal(is_osi_approved, datatype=XSD.boolean)))

        # Add FSF Libre status
        is_fsf_libre = license_data.get("isFsfLibre")
        if is_fsf_libre is not None:
            self.graph.add((license_uri, SPDX.isFsfLibre, Literal(is_fsf_libre, datatype=XSD.boolean)))

        # Add comments
        comments = license_data.get("licenseComments") or license_data.get("comment")
        if comments:
            self.graph.add((license_uri, RDFS.comment, Literal(comments)))

        # Add reference number
        ref_number = license_data.get("referenceNumber")
        if ref_number is not None:
            self.graph.add((license_uri, SCHEMA.position, Literal(ref_number, datatype=XSD.integer)))

        # Add seeAlso references
        see_also_list = license_data.get("seeAlso", [])
        for see_also_url in see_also_list:
            if see_also_url:
                self.graph.add((license_uri, RDFS.seeAlso, URIRef(see_also_url)))

        # Add crossRef data
        cross_refs = license_data.get("crossRef", [])
        for idx, cross_ref in enumerate(cross_refs):
            self._add_cross_reference(license_uri, cross_ref, idx)

        # Add details URL
        details_url = license_data.get("detailsUrl")
        if details_url:
            self.graph.add((license_uri, SPDX.detailsUrl, URIRef(details_url)))

        # Add reference URL
        reference_url = license_data.get("reference")
        if reference_url:
            self.graph.add((license_uri, DCTERMS.references, URIRef(reference_url)))

        return self.graph

    def _add_cross_reference(self, license_uri: URIRef, cross_ref: Dict[str, Any], index: int):
        """
        Add cross reference information as a blank node.

        Args:
            license_uri: The license URI
            cross_ref: Dictionary containing cross reference data
            index: Index of the cross reference
        """
        cross_ref_node = BNode()
        self.graph.add((license_uri, SPDX.crossRef, cross_ref_node))
        self.graph.add((cross_ref_node, RDF.type, SPDX.CrossRef))

        # Add URL
        url = cross_ref.get("url")
        if url:
            self.graph.add((cross_ref_node, SPDX.url, URIRef(url)))

        # Add match status
        match = cross_ref.get("match")
        if match:
            self.graph.add((cross_ref_node, SPDX.match, Literal(match)))

        # Add validity status
        is_valid = cross_ref.get("isValid")
        if is_valid is not None:
            self.graph.add((cross_ref_node, SPDX.isValid, Literal(is_valid, datatype=XSD.boolean)))

        # Add live status
        is_live = cross_ref.get("isLive")
        if is_live is not None:
            self.graph.add((cross_ref_node, SPDX.isLive, Literal(is_live, datatype=XSD.boolean)))

        # Add wayback link status
        is_wayback = cross_ref.get("isWayBackLink")
        if is_wayback is not None:
            self.graph.add((cross_ref_node, SPDX.isWayBackLink, Literal(is_wayback, datatype=XSD.boolean)))

        # Add timestamp
        timestamp = cross_ref.get("timestamp")
        if timestamp:
            self.graph.add((cross_ref_node, DCTERMS.date, Literal(timestamp, datatype=XSD.dateTime)))

        # Add order
        order = cross_ref.get("order")
        if order is not None:
            self.graph.add((cross_ref_node, SPDX.order, Literal(order, datatype=XSD.integer)))

    def transform_licenses_list(self, licenses_data: List[Dict[str, Any]]) -> Graph:
        """
        Transform a list of licenses to RDF.

        Args:
            licenses_data: List of license dictionaries

        Returns:
            RDFLib Graph object containing all licenses
        """
        # Reset graph for new transformation
        self.reset_graph()

        for license_data in licenses_data:
            license_uri_str = license_data.get("uri")
            if not license_uri_str:
                logging.warning(f"Skipping license without URI: {license_data.get('licenseId')}")
                continue

            license_uri = URIRef(license_uri_str)

            # Add minimal information for list view
            self.graph.add((license_uri, RDF.type, SPDX.License))

            license_id = license_data.get("licenseId")
            if license_id:
                self.graph.add((license_uri, SPDX.licenseId, Literal(license_id)))

            name = license_data.get("name")
            if name:
                self.graph.add((license_uri, SPDX.name, Literal(name)))
                self.graph.add((license_uri, RDFS.label, Literal(name)))

            # Add boolean flags
            is_deprecated = license_data.get("isDeprecatedLicenseId", False)
            self.graph.add((license_uri, SPDX.isDeprecatedLicenseId, Literal(is_deprecated, datatype=XSD.boolean)))

            is_osi_approved = license_data.get("isOsiApproved", False)
            self.graph.add((license_uri, SPDX.isOsiApproved, Literal(is_osi_approved, datatype=XSD.boolean)))

            is_fsf_libre = license_data.get("isFsfLibre")
            if is_fsf_libre is not None:
                self.graph.add((license_uri, SPDX.isFsfLibre, Literal(is_fsf_libre, datatype=XSD.boolean)))

            # Add reference number
            ref_number = license_data.get("referenceNumber")
            if ref_number is not None:
                self.graph.add((license_uri, SCHEMA.position, Literal(ref_number, datatype=XSD.integer)))

            # Add details URL
            details_url = license_data.get("detailsUrl")
            if details_url:
                self.graph.add((license_uri, SPDX.detailsUrl, URIRef(details_url)))

            # Add reference URL
            reference_url = license_data.get("reference")
            if reference_url:
                self.graph.add((license_uri, DCTERMS.references, URIRef(reference_url)))

            # Add seeAlso
            see_also_list = license_data.get("seeAlso", [])
            for see_also_url in see_also_list:
                if see_also_url:
                    self.graph.add((license_uri, RDFS.seeAlso, URIRef(see_also_url)))

        return self.graph

    def serialize(self, format: str = "turtle") -> str:
        """
        Serialize the graph to a string in the specified format.

        Args:
            format: RDF serialization format. Options:
                   - "turtle" (default, .ttl)
                   - "xml" (RDF/XML, .rdf)
                   - "json-ld" (JSON-LD, .jsonld)
                   - "nt" (N-Triples, .nt)
                   - "n3" (Notation3, .n3)

        Returns:
            Serialized RDF as string
        """
        format_map = {
            "turtle": "turtle",
            "ttl": "turtle",
            "xml": "xml",
            "rdf": "xml",
            "rdfxml": "xml",
            "json-ld": "json-ld",
            "jsonld": "json-ld",
            "nt": "nt",
            "ntriples": "nt",
            "n3": "n3"
        }

        rdf_format = format_map.get(format.lower(), "turtle")

        try:
            return self.graph.serialize(format=rdf_format)
        except Exception as e:
            logging.error(f"Failed to serialize graph to {format}: {e}")
            raise

    def save_to_file(self, filepath: str, format: str = "turtle"):
        """
        Save the graph to a file.

        Args:
            filepath: Path to output file
            format: RDF serialization format
        """
        try:
            serialized = self.serialize(format=format)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(serialized)
            logging.info(f"RDF saved to {filepath} in {format} format")
        except Exception as e:
            logging.error(f"Failed to save RDF to file {filepath}: {e}")
            raise


def json_to_rdf(license_data: Dict[str, Any], format: str = "turtle") -> str:
    """
    Convenience function to convert a single license JSON to RDF string.

    Args:
        license_data: Dictionary containing license information
        format: RDF serialization format

    Returns:
        Serialized RDF as string
    """
    transformer = RDFTransformer()
    transformer.transform_license(license_data)
    return transformer.serialize(format=format)


def json_list_to_rdf(licenses_data: List[Dict[str, Any]], format: str = "turtle") -> str:
    """
    Convenience function to convert a list of licenses JSON to RDF string.

    Args:
        licenses_data: List of license dictionaries
        format: RDF serialization format

    Returns:
        Serialized RDF as string
    """
    transformer = RDFTransformer()
    transformer.transform_licenses_list(licenses_data)
    return transformer.serialize(format=format)

