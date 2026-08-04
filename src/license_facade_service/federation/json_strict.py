from __future__ import annotations

import json
from typing import Any


class DuplicateJsonKeyError(ValueError):
    pass


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateJsonKeyError(f"Duplicate JSON key: {key}")
        obj[key] = value
    return obj


def loads_json_no_duplicates(payload: bytes) -> Any:
    return json.loads(payload.decode("utf-8"), object_pairs_hook=_object_pairs_no_duplicates)
