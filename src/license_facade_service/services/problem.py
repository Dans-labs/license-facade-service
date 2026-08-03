from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


class ProblemDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str = Field(default="about:blank")
    title: str
    status: int
    detail: str
    instance: str | None = None


def problem_response(
    *,
    status: int,
    title: str,
    detail: str,
    instance: str | None = None,
    type_uri: str = "about:blank",
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    payload = ProblemDetails(
        type=type_uri,
        title=title,
        status=status,
        detail=detail,
        instance=instance,
    ).model_dump(exclude_none=True)
    if extra:
        payload.update(extra)
    return JSONResponse(
        status_code=status,
        content=payload,
        media_type="application/problem+json",
    )

