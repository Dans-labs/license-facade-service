from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import jsonschema

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "vendor" / "spdx" / "3.0.1" / "spdx-json-schema.json"
EXPECTED_SCHEMA_SHA256 = "571dd17d52ad567cb5b44c2fdf0c57f013d08584f00e4f30b4f744dcca0fbb4c"


def _normalized_schema_sha256(schema_bytes: bytes) -> str:
    # Keep digest stable across Git checkout line-ending policies.
    return hashlib.sha256(schema_bytes.replace(b"\r\n", b"\n")).hexdigest()


class SpdxStructuralValidationError(ValueError):
    def __init__(self, message: str, *, errors: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.errors = errors or []


class Spdx301StructuralValidator:
    def __init__(self, schema_path: Path | str = SCHEMA_PATH) -> None:
        self.schema_path = Path(schema_path)
        self._schema_cache: dict[str, Any] | None = None
        self._validator_cache: Any | None = None
        self._load_schema()

    def _load_schema(self) -> None:
        if not self.schema_path.is_file():
            raise SpdxStructuralValidationError(f"SPDX schema not found at {self.schema_path}")
        schema_bytes = self.schema_path.read_bytes()
        digest = _normalized_schema_sha256(schema_bytes)
        if digest != EXPECTED_SCHEMA_SHA256:
            raise SpdxStructuralValidationError(
                f"SPDX schema digest mismatch: expected {EXPECTED_SCHEMA_SHA256}, got {digest}."
            )
        schema = json.loads(schema_bytes.decode("utf-8"))
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SpdxStructuralValidationError("Vendored SPDX schema is not a Draft 2020-12 schema.")
        refs: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "$ref":
                        ref = str(value)
                        refs.append(ref)
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(schema)
        non_internal = [ref for ref in refs if ref and not ref.startswith("#")]
        if non_internal:
            raise SpdxStructuralValidationError(
                "Vendored SPDX schema contains non-internal $ref values that would require network access: "
                f"{non_internal[:5]}"
            )
        self._schema_cache = schema
        self._validator_cache = jsonschema.Draft202012Validator(schema)

    @property
    def schema(self) -> dict[str, Any]:
        if self._schema_cache is None:
            raise SpdxStructuralValidationError("SPDX schema is not loaded.")
        return deepcopy(self._schema_cache)

    def validate(self, document: Mapping[str, Any]) -> None:
        if self._validator_cache is None:
            raise SpdxStructuralValidationError("SPDX validator not initialized.")
        if not isinstance(document, Mapping):
            raise SpdxStructuralValidationError("SPDX document must be a mapping.")
        if document.get("@context") != "https://spdx.org/rdf/3.0.1/spdx-context.jsonld":
            raise SpdxStructuralValidationError("SPDX document @context is not the official 3.0.1 context.")
        errors = sorted(self._validator_cache.iter_errors(document), key=lambda error: list(error.path))
        if errors:
            sanitized = []
            for error in errors[:20]:
                sanitized.append({
                    "path": list(error.path),
                    "message": error.message,
                })
            raise SpdxStructuralValidationError("SPDX document failed structural validation.", errors=sanitized)


__all__ = [
    "EXPECTED_SCHEMA_SHA256",
    "SCHEMA_PATH",
    "Spdx301StructuralValidator",
    "SpdxStructuralValidationError",
    "_normalized_schema_sha256",
]
