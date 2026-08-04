from __future__ import annotations

import hashlib
from typing import Any

from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256_hex(value: Any) -> str:
    return sha256_hex(canonicalize_to_bytes(value))
