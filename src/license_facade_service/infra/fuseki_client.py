"""
Apache Jena Fuseki Integration Module

This module provides functionality to interact with Apache Jena Fuseki
for storing and querying RDF license data.
"""

import logging
import os
from typing import Optional, Dict, Any
import httpx
from rdflib import Graph


class FusekiClient:
    """Client for Apache Jena Fuseki SPARQL server."""

    def __init__(
        self,
        fuseki_url: Optional[str] = None,
        dataset: str = "licenses",
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 30.0
    ):
        """
        Initialize Fuseki client.

        Args:
            fuseki_url: Base URL of Fuseki server (e.g., http://localhost:3030)
            dataset: Dataset name in Fuseki
            username: Fuseki admin username
            password: Fuseki admin password
            timeout: Request timeout in seconds
        """
        self.fuseki_url = fuseki_url or os.getenv(
            "FUSEKI_URL", "http://localhost:3030"
        )
        self.dataset = dataset
        self.username = username or os.getenv("FUSEKI_USER", "admin")
        self.password = password or os.getenv("FUSEKI_PASSWORD", "admin")
        self.timeout = timeout
        self.data_endpoint = f"{self.fuseki_url}/{dataset}/data"
        self.query_endpoint = f"{self.fuseki_url}/{dataset}/query"
        self.update_endpoint = f"{self.fuseki_url}/{dataset}/update"

        # Create auth object
        self.auth = httpx.BasicAuth(self.username, self.password)

        logging.info(
            f"Fuseki client initialized: {self.fuseki_url}/{dataset} (user: {self.username})"
        )

    async def check_connection(self) -> bool:
        """
        Check if Fuseki server is accessible.

        Returns:
            True if server is accessible, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.fuseki_url}/$/ping")
                return response.status_code == 200
        except Exception as e:
            logging.warning(f"Cannot connect to Fuseki server: {e}")
            return False

    async def dataset_exists(self) -> bool:
        """
        Check if the dataset exists in Fuseki.

        Returns:
            True if dataset exists, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.fuseki_url}/$/datasets", auth=self.auth)
                if response.status_code == 200:
                    datasets = response.json()
                    dataset_names = [licenses["licenses.name"].strip("/") for licenses in datasets.get("datasets", [])]
                    return self.dataset in dataset_names
        except Exception as e:
            logging.warning(f"Error checking dataset existence: {e}")
        return False

    async def create_dataset(self) -> bool:
        """
        Create a new dataset in Fuseki.

        Returns:
            True if dataset was created or already exists, False on error
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.fuseki_url}/$/datasets",
                    data={
                        "dbName": self.dataset,
                        "dbType": "tdb2"
                    },
                    auth=self.auth
                )
                if response.status_code in (200, 201):
                    logging.info(f"Fuseki dataset '{self.dataset}' created successfully")
                    return True
                elif response.status_code == 409:
                    logging.info(f"Fuseki dataset '{self.dataset}' already exists")
                    return True
                else:
                    logging.error(
                        f"Failed to create dataset: {response.status_code} - {response.text}"
                    )
                    return False
        except Exception as e:
            logging.error(f"Error creating dataset: {e}")
            return False

    async def upload_rdf(
        self,
        rdf_data: str,
        content_type: str = "text/turtle",
        graph_uri: Optional[str] = None
    ) -> bool:
        """
        Upload RDF data to Fuseki.

        Args:
            rdf_data: RDF data as string
            content_type: MIME type of RDF data (text/turtle, application/rdf+xml, etc.)
            graph_uri: Named graph URI (None for default graph)

        Returns:
            True if upload successful, False otherwise
        """
        try:
            headers = {"Content-Type": content_type}

            # Add graph parameter if specified
            params = {}
            if graph_uri:
                params["graph"] = graph_uri

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.data_endpoint,
                    content=rdf_data,
                    headers=headers,
                    params=params,
                    auth=self.auth
                )

                if response.status_code in (200, 201, 204):
                    logging.debug(f"RDF data uploaded successfully to {self.dataset}")
                    return True
                else:
                    logging.error(
                        f"Failed to upload RDF: {response.status_code} - {response.text}"
                    )
                    return False
        except Exception as e:
            logging.error(f"Error uploading RDF data: {e}")
            return False

    async def upload_graph(
        self,
        graph: Graph,
        format: str = "turtle",
        graph_uri: Optional[str] = None
    ) -> bool:
        """
        Upload an RDFLib graph to Fuseki.

        Args:
            graph: RDFLib Graph object
            format: Serialization format (turtle, xml, json-ld, nt)
            graph_uri: Named graph URI (None for default graph)

        Returns:
            True if upload successful, False otherwise
        """
        try:
            # Serialize graph
            rdf_data = graph.serialize(format=format)

            # Determine content type
            content_types = {
                "turtle": "text/turtle",
                "xml": "application/rdf+xml",
                "json-ld": "application/ld+json",
                "nt": "application/n-triples",
                "n3": "text/n3"
            }
            content_type = content_types.get(format, "text/turtle")

            return await self.upload_rdf(rdf_data, content_type, graph_uri)
        except Exception as e:
            logging.error(f"Error uploading graph: {e}")
            return False

    async def clear_dataset(self) -> bool:
        """
        Clear all data from the dataset.

        Returns:
            True if successful, False otherwise
        """
        try:
            sparql_update = "CLEAR ALL"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.update_endpoint,
                    data=sparql_update,
                    headers={"Content-Type": "application/sparql-update"},
                    auth=self.auth
                )

                if response.status_code in (200, 204):
                    logging.info(f"Dataset '{self.dataset}' cleared successfully")
                    return True
                else:
                    logging.error(
                        f"Failed to clear dataset: {response.status_code} - {response.text}"
                    )
                    return False
        except Exception as e:
            logging.error(f"Error clearing dataset: {e}")
            return False

    async def query(self, sparql_query: str) -> Optional[Dict[str, Any]]:
        """
        Execute a SPARQL query.

        Args:
            sparql_query: SPARQL query string

        Returns:
            Query results as dictionary, or None on error
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.query_endpoint,
                    data=sparql_query,
                    headers={
                        "Content-Type": "application/sparql-query",
                        "Accept": "application/sparql-results+json"
                    },
                    auth=self.auth
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logging.error(
                        f"Query failed: {response.status_code} - {response.text}"
                    )
                    return None
        except Exception as e:
            logging.error(f"Error executing query: {e}")
            return None

    async def count_triples(self) -> Optional[int]:
        """
        Count total number of triples in the dataset.

        Returns:
            Number of triples, or None on error
        """
        sparql = "SELECT (COUNT(*) as ?count) WHERE { ?s ?p ?o }"
        result = await self.query(sparql)

        if result and "results" in result and "bindings" in result["results"]:
            bindings = result["results"]["bindings"]
            if bindings and "count" in bindings[0]:
                return int(bindings[0]["count"]["value"])

        return None

    async def get_license_count(self) -> Optional[int]:
        """
        Count number of licenses in the dataset.

        Returns:
            Number of licenses, or None on error
        """
        sparql = """
        PREFIX spdx: <http://spdx.org/rdf/terms#>
        SELECT (COUNT(DISTINCT ?license) as ?count)
        WHERE {
            ?license a spdx:License .
        }
        """
        result = await self.query(sparql)

        if result and "results" in result and "bindings" in result["results"]:
            bindings = result["results"]["bindings"]
            if bindings and "count" in bindings[0]:
                return int(bindings[0]["count"]["value"])

        return None


# Global Fuseki client instance
_fuseki_client: Optional[FusekiClient] = None


def get_fuseki_client() -> FusekiClient:
    """
    Get the global Fuseki client instance.

    Returns:
        FusekiClient instance
    """
    global _fuseki_client
    if _fuseki_client is None:
        _fuseki_client = FusekiClient()
    return _fuseki_client


def set_fuseki_client(client: FusekiClient):
    """
    Set the global Fuseki client instance.

    Args:
        client: FusekiClient instance
    """
    global _fuseki_client
    _fuseki_client = client

