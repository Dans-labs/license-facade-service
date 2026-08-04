from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class CanonicalLicenseIdentity(BaseModel):
    authorityNodeId: str
    localId: str
    version: str
    canonicalId: str
    resolvingUuid: str


class JwkKey(BaseModel):
    kty: Literal["OKP"]
    use: Literal["sig"] = "sig"
    crv: Literal["Ed25519"]
    alg: Literal["EdDSA"]
    kid: str
    x: str


class JwksResponse(BaseModel):
    keys: list[JwkKey] = Field(default_factory=list)


class SignatureEnvelope(BaseModel):
    kid: str
    alg: Literal["EdDSA"] = "EdDSA"
    encoding: Literal["base64url"] = "base64url"
    value: str


class SignedDomainObject(BaseModel):
    digestSha256: str
    canonicalization: Literal["RFC8785-JCS"] = "RFC8785-JCS"
    encoding: Literal["utf-8"] = "utf-8"
    signature: SignatureEnvelope


class SignedFederationRecordPayload(BaseModel):
    nodeId: str
    canonicalId: str
    authorityNodeId: str
    localId: str
    version: str
    publishedAt: datetime
    payload: dict[str, Any]
    payloadDigestSha256: str


class SignedFederationChangeEventPayload(BaseModel):
    nodeId: str
    eventId: str
    eventPosition: int
    operation: Literal["upsert", "deprecate", "tombstone"]
    generatedAt: datetime
    record: SignedFederationRecordPayload
    provenance: Literal["publication", "backfill"] = "publication"
    backfillCreatedAt: datetime | None = None


class FederationChangeEventItem(BaseModel):
    payload: SignedFederationChangeEventPayload
    signed: SignedDomainObject


class SignedChangeBatchEnvelopePayload(BaseModel):
    nodeId: str
    firstEventPosition: int | None = None
    lastEventPosition: int | None = None
    requestCursor: str | None = None
    nextCursor: str | None = None
    eventDigests: list[str] = Field(default_factory=list)
    snapshotWatermark: int


class SignedChangeBatchEnvelope(BaseModel):
    payload: SignedChangeBatchEnvelopePayload
    signed: SignedDomainObject


class FederationRecordResponse(BaseModel):
    record: SignedFederationRecordPayload
    signed: SignedDomainObject
    currentState: Literal["published", "deprecated", "tombstoned"]
    latestEventPosition: int
    latestEventDigestSha256: str


class FederationCatalogItem(BaseModel):
    canonicalId: str
    encodedId: str
    authorityNodeId: str
    version: str
    publicationState: Literal["published", "deprecated", "tombstoned"]
    publishedAt: datetime
    payloadDigestSha256: str
    eventPosition: int


class FederationCatalogResponse(BaseModel):
    items: list[FederationCatalogItem] = Field(default_factory=list)
    limit: int
    hasMore: bool
    nextCursor: str | None = None
    snapshotWatermark: int
    etag: str


class FederationChangesResponse(BaseModel):
    events: list[FederationChangeEventItem] = Field(default_factory=list)
    limit: int
    hasMore: bool
    nextCursor: str | None = None
    resumeCursor: str
    snapshotWatermark: int
    envelope: SignedChangeBatchEnvelope | None = None
    etag: str


class FederationDiscoveryResponse(BaseModel):
    protocolVersion: str
    nodeId: str
    nodeName: str
    operator: str
    publicBaseUrl: str
    currentSigningKid: str
    jwksUrl: str
    catalogUrl: str
    changesUrl: str
    recordUrlTemplate: str
    conformance: list[str] = Field(default_factory=list)
