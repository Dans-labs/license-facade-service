from __future__ import annotations

from src.license_facade_service.federation.canonical_json import canonicalize_to_text
from src.license_facade_service.federation.digests import canonical_json_sha256_hex, sha256_hex


def test_canonical_json_is_deterministic():
    payload_a = {"b": 2, "a": [3, {"z": 1, "y": 2}]}
    payload_b = {"a": [3, {"y": 2, "z": 1}], "b": 2}
    canonical_a = canonicalize_to_text(payload_a)
    canonical_b = canonicalize_to_text(payload_b)
    assert canonical_a == canonical_b
    assert canonical_a == '{"a":[3,{"y":2,"z":1}],"b":2}'


def test_sha256_vectors_are_stable():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert canonical_json_sha256_hex({"a": 1, "b": 2}) == "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
