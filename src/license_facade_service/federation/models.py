from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CanonicalLicenseIdentity(BaseModel):
    authorityNodeId: str
    localId: str
    version: str
    canonicalId: str
    resolvingUuid: str


class FederationPeer(BaseModel):
    peerNodeId: str
    baseUrl: str
    jwksUrl: str
    peerName: str
    operator: str | None = None
    trustStatus: Literal["trusted", "blocked", "pending"] = "trusted"


class FederationProvenance(BaseModel):
    provenanceType: str
    sourceNodeId: str | None = None
    sourceUri: str | None = None
    sourceDigestSha256: str | None = None
    assertedAt: datetime


class FederationRecord(BaseModel):
    authorityNodeId: str
    localId: str
    version: str
    canonicalId: str
    resolvingUuid: str
    payloadDigestSha256: str
    publishedAt: datetime | None = None
    isAuthoritative: bool


class FederationChangeEvent(BaseModel):
    eventSequence: int
    eventType: str
    authorityNodeId: str
    eventDigestSha256: str
    occurredAt: datetime


class JwkKey(BaseModel):
    kty: Literal["OKP"]
    use: Literal["sig"] = "sig"
    crv: Literal["Ed25519"]
    alg: Literal["EdDSA"]
    kid: str
    x: str
    status: str | None = None
    validFrom: datetime | None = None
    validUntil: datetime | None = None


class JwksResponse(BaseModel):
    keys: list[JwkKey] = Field(default_factory=list)
