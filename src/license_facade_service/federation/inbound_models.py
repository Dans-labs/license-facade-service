from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from src.license_facade_service.federation.models import (
    JwkKey,
    SignedDomainObject,
    SignedFederationChangeEventPayload,
    SignedFederationRecordPayload,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RemoteDiscoveryResponse(StrictModel):
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


class RemoteJwksResponse(StrictModel):
    keys: list[JwkKey] = Field(default_factory=list)


class RemoteChangeEventItem(StrictModel):
    payload: SignedFederationChangeEventPayload
    signed: SignedDomainObject


class RemoteChangesResponse(StrictModel):
    events: list[RemoteChangeEventItem] = Field(default_factory=list)
    limit: int
    hasMore: bool
    nextCursor: str | None = None
    resumeCursor: str
    snapshotWatermark: int
    envelope: dict[str, Any] | None = None


class RemoteRecordResponse(StrictModel):
    record: SignedFederationRecordPayload
    signed: SignedDomainObject
    currentState: Literal["published", "deprecated", "tombstoned"]
    latestEventPosition: int
    latestEventDigestSha256: str


class PeerVerificationKeyRequest(StrictModel):
    kid: str
    fingerprint: str


class PeerCreateRequest(StrictModel):
    peerNodeId: str
    baseUrl: str
    peerName: str
    operatorName: str
    verificationKey: PeerVerificationKeyRequest | None = None
    allowPrivateNetwork: bool = False
    allowedHostnames: list[str] = Field(default_factory=list)
    allowedCidrs: list[str] = Field(default_factory=list)
    demoTofuConfirm: bool = False


class PeerPatchRequest(StrictModel):
    baseUrl: str | None = None
    peerName: str | None = None
    operatorName: str | None = None
    syncEnabled: bool | None = None
    trustStatus: Literal["trusted", "disabled", "archived"] | None = None
    verificationKey: PeerVerificationKeyRequest | None = None
    allowPrivateNetwork: bool | None = None
    allowedHostnames: list[str] | None = None
    allowedCidrs: list[str] | None = None


class PeerResponse(StrictModel):
    id: UUID
    peerNodeId: str
    baseUrl: str
    peerName: str
    operatorName: str | None
    trustStatus: str
    syncEnabled: bool
    lastSyncAttemptAt: datetime | None = None
    lastSyncSuccessAt: datetime | None = None
    lastSyncStatus: str | None = None
    lastSyncErrorCode: str | None = None
    expectedKeyKid: str | None = None
    expectedKeyFingerprint: str | None = None
    archivedAt: datetime | None = None


class PeerListResponse(StrictModel):
    items: list[PeerResponse]
    limit: int
    offset: int
    total: int


class SyncResultResponse(StrictModel):
    status: Literal["complete", "partial", "failed", "already-running"]
    pagesProcessed: int
    eventsProcessed: int
    importedRecords: int
    cursorBefore: str | None = None
    cursorAfter: str | None = None
    detail: str | None = None


class AdminStatusResponse(StrictModel):
    nodeId: str | None
    federationEnabled: bool
    inboundEnabled: bool
    peers: int
    trustedPeers: int
    disabledPeers: int
    importedRecords: int
    inboundEventsAccepted: int
    inboundEventsRejected: int
    workerIntervalSeconds: int
    maxSyncSeconds: int


class ImportedRecordResponse(StrictModel):
    canonicalId: str
    authorityNodeId: str
    localId: str
    version: str
    isAuthoritative: bool
    lifecycleState: str
    payloadDigestSha256: str
    verificationStatus: str | None = None
    sourceEventId: str | None = None
    sourceEventPosition: int | None = None
    sourceSignatureKid: str | None = None
    lastVerifiedAt: datetime | None = None


class ImportedRecordListResponse(StrictModel):
    items: list[ImportedRecordResponse]
    total: int


class AdminPublishRequest(StrictModel):
    localId: str
    version: str
    payload: dict[str, Any]
