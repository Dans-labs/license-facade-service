from __future__ import annotations

from typing import Any

import jcs


def canonicalize_to_bytes(value: Any) -> bytes:
    return jcs.canonicalize(value)


def canonicalize_to_text(value: Any) -> str:
    return canonicalize_to_bytes(value).decode("utf-8")
