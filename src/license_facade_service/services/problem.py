from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


class ProblemDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str = Field(
        default="about:blank",
        description="Problem type URI identifying the error category.",
        examples=["https://eosc-eden.eu/problems/resolution-not-found"],
    )
    title: str = Field(description="Short human-readable summary of the problem.", examples=["Resolution Not Found"])
    status: int = Field(description="HTTP status code generated for this problem response.", examples=[404])
    detail: str = Field(
        description="Human-readable explanation specific to this occurrence of the problem.",
        examples=["No record or fallback SPDX entry could be resolved for the supplied identifier."],
    )
    instance: str | None = Field(
        default=None,
        description="Request URI for the failing operation, when available.",
        examples=["https://license.example.org/api/v1/licenses/resolution?identifier=MIT"],
    )


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
