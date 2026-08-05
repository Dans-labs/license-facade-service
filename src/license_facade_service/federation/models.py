from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class CanonicalLicenseIdentity(BaseModel):
    authorityNodeId: str = Field(description="Authority node UUID that owns the canonical licence identity.")
    localId: str = Field(description="Authority-scoped local licence identifier.")
    version: str = Field(description="Authority-scoped record version.")
    canonicalId: str = Field(description="Canonical federation identifier derived from authority, local ID, and version.")
    resolvingUuid: str = Field(description="Deterministic UUID used as a secondary stable resolver key.")


class JwkKey(BaseModel):
    kty: Literal["OKP"] = Field(description="JSON Web Key type. Only OKP is supported for Ed25519 signing keys.")
    use: Literal["sig"] = "sig"
    crv: Literal["Ed25519"] = Field(description="Ed25519 elliptic curve identifier.")
    alg: Literal["EdDSA"] = Field(description="Signature algorithm advertised for verification.")
    kid: str = Field(description="Public key identifier used in signed outbound discovery, records, and change events.")
    x: str = Field(description="Base64url-encoded Ed25519 public key material.", examples=["11qYAYdk-e5o0Lx4Y4kPv4QwqW9As2n3l2sYvQvTz3A"])


class JwksResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "keys": [
                    {
                        "kty": "OKP",
                        "use": "sig",
                        "crv": "Ed25519",
                        "alg": "EdDSA",
                        "kid": "node-a-k1",
                        "x": "11qYAYdk-e5o0Lx4Y4kPv4QwqW9As2n3l2sYvQvTz3A",
                    }
                ]
            }
        }
    )

    keys: list[JwkKey] = Field(default_factory=list, description="Public verification keys currently exposed by the node. Private keys are never returned.")


class SignatureEnvelope(BaseModel):
    kid: str = Field(description="Key identifier matching a JWKS entry.")
    alg: Literal["EdDSA"] = Field(default="EdDSA", description="Signature algorithm used to sign the canonical bytes.")
    encoding: Literal["base64url"] = Field(default="base64url", description="Encoding used for the detached signature value.")
    value: str = Field(description="Detached base64url-encoded Ed25519 signature.", examples=["Z3Vlc3Qtc2lnbmF0dXJlLWV4YW1wbGU"])


class SignedDomainObject(BaseModel):
    digestSha256: str = Field(description="SHA-256 digest of the canonical JSON payload.", examples=["0f9c753d2c4f0fd0ab3c6d690be2284a5a7d4bb55a0b63d084af449e0bdfaf8b"])
    canonicalization: Literal["RFC8785-JCS"] = Field(default="RFC8785-JCS", description="Canonical JSON algorithm applied before digesting and signing.")
    encoding: Literal["utf-8"] = Field(default="utf-8", description="Text encoding used for the canonical payload bytes.")
    signature: SignatureEnvelope = Field(description="Detached signature metadata and value for the canonical payload.")


class SignedFederationRecordPayload(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "nodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "canonicalId": "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:MIT:1",
                "authorityNodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "localId": "MIT",
                "version": "1",
                "publishedAt": "2026-08-04T10:15:00Z",
                "payload": {"licenseId": "MIT", "name": "MIT License"},
                "payloadDigestSha256": "0f9c753d2c4f0fd0ab3c6d690be2284a5a7d4bb55a0b63d084af449e0bdfaf8b",
            }
        }
    )

    nodeId: str = Field(description="Federation node UUID that signed and published this record.")
    canonicalId: str = Field(description="Canonical licence identifier used across federation transport.")
    authorityNodeId: str = Field(description="Authority node that owns the record semantically.")
    localId: str = Field(description="Authority-local licence identifier.")
    version: str = Field(description="Authority-local version string.")
    publishedAt: datetime = Field(description="Timestamp at which the record was published or last materialized.")
    payload: dict[str, Any] = Field(description="Business payload carried by the authoritative record.")
    payloadDigestSha256: str = Field(description="Digest of the business payload stored alongside the signed wrapper.")


class SignedFederationChangeEventPayload(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "nodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "eventId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "eventPosition": 42,
                "operation": "upsert",
                "generatedAt": "2026-08-04T10:15:05Z",
                "record": {
                    "nodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "canonicalId": "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:MIT:1",
                    "authorityNodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "localId": "MIT",
                    "version": "1",
                    "publishedAt": "2026-08-04T10:15:00Z",
                    "payload": {"licenseId": "MIT", "name": "MIT License"},
                    "payloadDigestSha256": "0f9c753d2c4f0fd0ab3c6d690be2284a5a7d4bb55a0b63d084af449e0bdfaf8b",
                },
                "provenance": "publication",
                "backfillCreatedAt": None,
            }
        }
    )

    nodeId: str = Field(description="Federation node UUID that emitted the change event.")
    eventId: str = Field(description="Immutable event UUID assigned by the publishing node.")
    eventPosition: int = Field(description="Monotonic change-feed position within the publishing node.")
    operation: Literal["upsert", "deprecate", "tombstone"] = Field(description="Lifecycle operation represented by this event.")
    generatedAt: datetime = Field(description="Timestamp at which the event wrapper was generated.")
    record: SignedFederationRecordPayload = Field(description="Signed record payload carried by the change event.")
    provenance: Literal["publication", "backfill"] = Field(default="publication", description="Reason this event entered the outbound feed.")
    backfillCreatedAt: datetime | None = Field(default=None, description="Timestamp of the original event when this event was backfilled.")


class FederationChangeEventItem(BaseModel):
    payload: SignedFederationChangeEventPayload = Field(description="Unsigned event payload that clients must canonicalize, digest, and verify.")
    signed: SignedDomainObject = Field(description="Digest and signature metadata for the event payload.")


class SignedChangeBatchEnvelopePayload(BaseModel):
    nodeId: str = Field(description="Federation node UUID that emitted this batch envelope.")
    firstEventPosition: int | None = Field(default=None, description="First event position included in the page.")
    lastEventPosition: int | None = Field(default=None, description="Last event position included in the page.")
    requestCursor: str | None = Field(default=None, description="Opaque cursor supplied by the client for this page request.")
    nextCursor: str | None = Field(default=None, description="Opaque cursor to request the next page of events.")
    eventDigests: list[str] = Field(default_factory=list, description="Ordered digests for the events included in the batch.")
    snapshotWatermark: int = Field(description="Stable watermark used to make page traversal deterministic.")


class SignedChangeBatchEnvelope(BaseModel):
    payload: SignedChangeBatchEnvelopePayload = Field(description="Unsigned metadata describing the event page.")
    signed: SignedDomainObject = Field(description="Digest and signature metadata for the page envelope.")


class FederationRecordResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "record": {
                    "nodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "canonicalId": "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:MIT:1",
                    "authorityNodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "localId": "MIT",
                    "version": "1",
                    "publishedAt": "2026-08-04T10:15:00Z",
                    "payload": {"licenseId": "MIT", "name": "MIT License"},
                    "payloadDigestSha256": "0f9c753d2c4f0fd0ab3c6d690be2284a5a7d4bb55a0b63d084af449e0bdfaf8b",
                },
                "signed": {
                    "digestSha256": "e7f2f2b8d35d0a2b2866d9aa1c9ca9bbca3a42ad1dcda6e0f2f66f3f1b676f4d",
                    "canonicalization": "RFC8785-JCS",
                    "encoding": "utf-8",
                    "signature": {
                        "kid": "node-a-k1",
                        "alg": "EdDSA",
                        "encoding": "base64url",
                        "value": "Z3Vlc3Qtc2lnbmF0dXJlLWV4YW1wbGU",
                    },
                },
                "currentState": "published",
                "latestEventPosition": 42,
                "latestEventDigestSha256": "c8da54d8d7e4c2ec7fd484cc4136d2fdabdb73385be53e3358ab7cb6648dcb7e",
            }
        }
    )

    record: SignedFederationRecordPayload = Field(description="Signed authoritative record body.")
    signed: SignedDomainObject = Field(description="Digest and detached signature for the record body.")
    currentState: Literal["published", "deprecated", "tombstoned"] = Field(description="Current lifecycle state of the authoritative record.")
    latestEventPosition: int = Field(description="Latest authoritative event position known for this record.")
    latestEventDigestSha256: str = Field(description="Digest of the latest authoritative change event affecting this record.")


class FederationCatalogItem(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "canonicalId": "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:MIT:1",
                "encodedId": "bGZzOmFhYWFhYWFhLWFhYWEtNGFhYS04YWFhLWFhYWFhYWFhYWFhYTpNSVQ6MQ",
                "authorityNodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "version": "1",
                "publicationState": "published",
                "publishedAt": "2026-08-04T10:15:00Z",
                "payloadDigestSha256": "0f9c753d2c4f0fd0ab3c6d690be2284a5a7d4bb55a0b63d084af449e0bdfaf8b",
                "eventPosition": 42,
            }
        }
    )

    canonicalId: str = Field(description="Canonical identifier for the authoritative record.")
    encodedId: str = Field(description="URL-safe encoded canonical identifier for the record download endpoint.")
    authorityNodeId: str = Field(description="Authority node that owns the record.")
    version: str = Field(description="Authority-scoped record version.")
    publicationState: Literal["published", "deprecated", "tombstoned"] = Field(description="Lifecycle state exposed in the authoritative outbound catalog.")
    publishedAt: datetime = Field(description="Timestamp at which the current version became effective.")
    payloadDigestSha256: str = Field(description="Digest of the business payload.")
    eventPosition: int = Field(description="Latest event position that contributed to this catalog item.")


class FederationCatalogResponse(BaseModel):
    items: list[FederationCatalogItem] = Field(default_factory=list, description="Authoritative records in the requested page.")
    limit: int = Field(description="Applied page size.")
    hasMore: bool = Field(description="Whether another page is available.")
    nextCursor: str | None = Field(default=None, description="Opaque keyset cursor for the next catalog page.")
    snapshotWatermark: int = Field(description="Stable watermark used to avoid skips or duplicates while paging.")
    etag: str = Field(description="Strong ETag for the response representation.")


class FederationChangesResponse(BaseModel):
    events: list[FederationChangeEventItem] = Field(default_factory=list, description="Signed change events included in the requested page.")
    limit: int = Field(description="Applied page size.")
    hasMore: bool = Field(description="Whether another page of changes is available.")
    nextCursor: str | None = Field(default=None, description="Opaque cursor to request the next page.")
    resumeCursor: str = Field(description="Opaque cursor that can safely resume from the last committed event position.")
    snapshotWatermark: int = Field(description="Watermark used to stabilize paging while the feed changes.")
    envelope: SignedChangeBatchEnvelope | None = Field(default=None, description="Optional signed envelope summarizing the returned event page.")
    etag: str = Field(description="Strong ETag for the response representation.")


class FederationDiscoveryResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "protocolVersion": "1.0",
                "nodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "nodeName": "Example Authority Node",
                "operator": "Example Operator",
                "publicBaseUrl": "https://node-a.example.org",
                "currentSigningKid": "node-a-k1",
                "jwksUrl": "https://node-a.example.org/.well-known/jwks.json",
                "catalogUrl": "https://node-a.example.org/api/v1/federation/catalog",
                "changesUrl": "https://node-a.example.org/api/v1/federation/changes",
                "recordUrlTemplate": "https://node-a.example.org/api/v1/federation/records/{encoded_id}",
                "conformance": ["phase1-foundation", "phase2-outbound", "phase3-inbound", "phase4-resolution"],
            }
        }
    )

    protocolVersion: str = Field(description="Advertised federation protocol version.")
    nodeId: str = Field(description="Stable UUID identifying this federation node.")
    nodeName: str = Field(description="Human-readable node name for administrators and peer enrollment.")
    operator: str = Field(description="Human-readable operator name for the node.")
    publicBaseUrl: str = Field(description="Base URL that peers should use when talking to this node.")
    currentSigningKid: str = Field(description="Currently active outbound signing key identifier.")
    jwksUrl: str = Field(description="URL of the public JWKS document containing verification keys.")
    catalogUrl: str = Field(description="URL of the authoritative record catalog endpoint.")
    changesUrl: str = Field(description="URL of the signed change-feed endpoint.")
    recordUrlTemplate: str = Field(description="URI template for fetching a single authoritative record by encoded canonical ID.")
    conformance: list[str] = Field(default_factory=list, description="Implemented federation feature set advertised by this node.")
