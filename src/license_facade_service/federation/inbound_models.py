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
    protocolVersion: str = Field(description="Advertised federation protocol version from the remote node.")
    nodeId: str = Field(description="Stable UUID identifying the remote node.")
    nodeName: str = Field(description="Human-readable node name exposed by the peer.")
    operator: str = Field(description="Human-readable operator name exposed by the peer.")
    publicBaseUrl: str = Field(description="Base URL peers should use when calling this node.")
    currentSigningKid: str = Field(description="Currently active signing key identifier advertised by the peer.")
    jwksUrl: str = Field(description="Remote JWKS endpoint exposing verification keys only.")
    catalogUrl: str = Field(description="Remote authoritative catalog endpoint.")
    changesUrl: str = Field(description="Remote signed changes endpoint.")
    recordUrlTemplate: str = Field(description="Remote URI template for fetching one authoritative record by encoded canonical ID.")
    conformance: list[str] = Field(default_factory=list, description="Federation features advertised by the remote node.")


class RemoteJwksResponse(StrictModel):
    keys: list[JwkKey] = Field(default_factory=list, description="Verification keys exposed by the remote node. Private signing material is never included.")


class RemoteChangeEventItem(StrictModel):
    payload: SignedFederationChangeEventPayload = Field(description="Unsigned change event payload received from a trusted peer.")
    signed: SignedDomainObject = Field(description="Digest and detached signature metadata for the change event payload.")


class RemoteChangesResponse(StrictModel):
    events: list[RemoteChangeEventItem] = Field(default_factory=list, description="Signed change events returned by the remote page request.")
    limit: int = Field(description="Applied page size.")
    hasMore: bool = Field(description="Whether another page of changes is available.")
    nextCursor: str | None = Field(default=None, description="Opaque cursor for the next page.")
    resumeCursor: str = Field(description="Opaque cursor that may be persisted after successful commit.")
    snapshotWatermark: int = Field(description="Stable page watermark emitted by the remote node.")
    envelope: dict[str, Any] | None = Field(default=None, description="Optional signed batch envelope summarizing the returned page.")


class RemoteRecordResponse(StrictModel):
    record: SignedFederationRecordPayload = Field(description="Unsigned authoritative record payload returned by the remote node.")
    signed: SignedDomainObject = Field(description="Digest and detached signature metadata for the record payload.")
    currentState: Literal["published", "deprecated", "tombstoned"] = Field(description="Lifecycle state at the remote authority.")
    latestEventPosition: int = Field(description="Latest authoritative event position known by the remote node.")
    latestEventDigestSha256: str = Field(description="Digest of the latest authoritative change event for the record.")


class PeerVerificationKeyRequest(StrictModel):
    kid: str = Field(description="Expected remote signing key identifier to pin during enrollment.", examples=["node-a-k1"])
    fingerprint: str = Field(
        description="Expected SHA-256 fingerprint of the remote Ed25519 public key.",
        examples=["c76e746a0f2b78e0bf2ca8f1478b1f087834b23499f9f8e640b8d89cd5233d7a"],
    )


class PeerCreateRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "peerNodeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "baseUrl": "https://node-a.example.org",
                "peerName": "Example Authority Node",
                "operatorName": "Example Operator",
                "verificationKey": {
                    "kid": "node-a-k1",
                    "fingerprint": "c76e746a0f2b78e0bf2ca8f1478b1f087834b23499f9f8e640b8d89cd5233d7a",
                },
                "allowPrivateNetwork": False,
                "allowedHostnames": ["node-a.example.org"],
                "allowedCidrs": [],
                "demoTofuConfirm": False,
            }
        },
    )

    peerNodeId: str = Field(description="Expected remote node UUID. Enrollment fails if discovery advertises a different node ID.")
    baseUrl: str = Field(description="Remote peer base URL. Production use should be HTTPS.", examples=["https://node-a.example.org"])
    peerName: str = Field(description="Friendly label stored locally for the trusted peer.")
    operatorName: str = Field(description="Friendly operator name stored locally for the trusted peer.")
    verificationKey: PeerVerificationKeyRequest | None = Field(
        default=None,
        description="Pinned remote verification key material required for explicit trust enrollment.",
    )
    allowPrivateNetwork: bool = Field(default=False, description="Allow private-network targets for controlled demos only.")
    allowedHostnames: list[str] = Field(default_factory=list, description="Additional hostnames explicitly allowed by SSRF protections.")
    allowedCidrs: list[str] = Field(default_factory=list, description="Additional CIDR ranges explicitly allowed by SSRF protections.")
    demoTofuConfirm: bool = Field(default=False, description="Unsafe demo-only confirmation for trust-on-first-use flows when enabled.")


class PeerPatchRequest(StrictModel):
    baseUrl: str | None = Field(default=None, description="Updated base URL for the peer.")
    peerName: str | None = Field(default=None, description="Updated friendly peer name.")
    operatorName: str | None = Field(default=None, description="Updated friendly operator name.")
    syncEnabled: bool | None = Field(default=None, description="Whether inbound synchronization from this peer is enabled.")
    trustStatus: Literal["trusted", "disabled", "archived"] | None = Field(
        default=None,
        description="Operational trust state used during normal resolution and synchronization.",
    )
    verificationKey: PeerVerificationKeyRequest | None = Field(default=None, description="Replacement pinned verification key metadata.")
    allowPrivateNetwork: bool | None = Field(default=None, description="Whether private-network targets are allowed for this peer.")
    allowedHostnames: list[str] | None = Field(default=None, description="Replacement hostname allow-list used by SSRF protections.")
    allowedCidrs: list[str] | None = Field(default=None, description="Replacement CIDR allow-list used by SSRF protections.")


class PeerResponse(StrictModel):
    id: UUID = Field(description="Local UUID assigned to the trusted peer configuration.")
    peerNodeId: str = Field(description="Remote node UUID that this peer must continue to advertise.")
    baseUrl: str = Field(description="Remote base URL currently configured for the peer.")
    peerName: str = Field(description="Friendly peer name stored locally.")
    operatorName: str | None = Field(default=None, description="Friendly operator name stored locally.")
    trustStatus: str = Field(description="Current trust/operational state of the peer.")
    syncEnabled: bool = Field(description="Whether normal synchronization from this peer is enabled.")
    lastSyncAttemptAt: datetime | None = Field(default=None, description="Timestamp of the most recent synchronization attempt.")
    lastSyncSuccessAt: datetime | None = Field(default=None, description="Timestamp of the most recent successful synchronization.")
    lastSyncStatus: str | None = Field(default=None, description="Status of the most recent synchronization attempt.")
    lastSyncErrorCode: str | None = Field(default=None, description="Last machine-readable synchronization error code, when available.")
    expectedKeyKid: str | None = Field(default=None, description="Pinned signing key identifier expected from the peer.")
    expectedKeyFingerprint: str | None = Field(default=None, description="Pinned signing key fingerprint expected from the peer.")
    archivedAt: datetime | None = Field(default=None, description="Timestamp at which the peer was archived, when applicable.")
    # Phase 5 — circuit breaker (all optional for backward compatibility)
    circuitState: str | None = Field(default=None, description="Current circuit breaker state.")
    circuitRequiresAdminReset: bool | None = Field(default=None, description="Whether the circuit requires admin intervention to reset.")
    circuitFailureCount: int | None = Field(default=None, description="Number of consecutive circuit failures.")
    circuitOpenedAt: datetime | None = Field(default=None, description="Timestamp at which the circuit was opened.")
    circuitNextAttemptAt: datetime | None = Field(default=None, description="Timestamp of the next permitted half-open probe attempt.")
    circuitLastFailureReason: str | None = Field(default=None, description="Machine-readable reason for the last circuit failure.")
    # Phase 5 — administrative suspension
    suspendedUntil: datetime | None = Field(default=None, description="Timestamp until which the peer is administratively suspended.")
    suspensionReason: str | None = Field(default=None, description="Human-readable reason for the administrative suspension.")
    # Phase 5 — peer key management
    lastKeyRefreshAt: datetime | None = Field(default=None, description="Timestamp of the most recent peer key refresh.")
    # Phase 5 — latest health (from most recent health snapshot)
    latestHealthStatus: str | None = Field(default=None, description="Health status from the most recent health probe snapshot.")
    latestCompatibilityStatus: str | None = Field(default=None, description="Compatibility status from the most recent health probe snapshot.")


class PeerListResponse(StrictModel):
    items: list[PeerResponse] = Field(description="Page of configured trusted peers.")
    limit: int = Field(description="Applied page size.")
    offset: int = Field(description="Applied page offset.")
    total: int = Field(description="Total number of configured peers.")


class SyncResultResponse(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "status": "complete",
                "pagesProcessed": 1,
                "eventsProcessed": 2,
                "importedRecords": 1,
                "cursorBefore": "v1.node-a-k1.before.example",
                "cursorAfter": "v1.node-a-k1.after.example",
                "detail": "Synchronization completed successfully.",
            }
        },
    )

    status: Literal["complete", "partial", "failed", "already-running", "skipped"] = Field(
        description="Overall synchronization outcome. `partial` means some data committed before a later failure. `already-running` indicates a conflicting lock.",
    )
    pagesProcessed: int = Field(description="Number of change-feed pages processed during the operation.")
    eventsProcessed: int = Field(description="Number of remote change events examined during the operation.")
    importedRecords: int = Field(description="Number of records newly imported or updated in PostgreSQL.")
    cursorBefore: str | None = Field(default=None, description="Persisted cursor before the synchronization attempt started.")
    cursorAfter: str | None = Field(default=None, description="Persisted cursor after successful commit of the latest page.")
    detail: str | None = Field(default=None, description="Additional human-readable outcome details.")


class AdminStatusResponse(StrictModel):
    nodeId: str | None = Field(default=None, description="Local federation node UUID, when configured.")
    federationEnabled: bool = Field(description="Whether federation features are enabled at runtime.")
    inboundEnabled: bool = Field(description="Whether inbound synchronization is enabled at runtime.")
    peers: int = Field(description="Total number of configured peers.")
    trustedPeers: int = Field(description="Number of peers currently in normal trusted operation.")
    disabledPeers: int = Field(description="Number of peers excluded from normal synchronization.")
    importedRecords: int = Field(description="Number of imported records retained in PostgreSQL.")
    inboundEventsAccepted: int = Field(description="Count of inbound events accepted and committed.")
    inboundEventsRejected: int = Field(description="Count of inbound events rejected during validation.")
    workerIntervalSeconds: int = Field(description="Configured background synchronization polling interval.")
    maxSyncSeconds: int = Field(description="Configured upper bound for one synchronization run.")
    # Phase 5 operational extension (all optional)
    protocolVersion: str | None = Field(default=None, description="Advertised local federation protocol version.")
    signingKeySummary: dict | None = Field(default=None, description="Signing key counts by lifecycle status.")
    peerSummary: dict | None = Field(default=None, description="Peer counts by circuit state, trust status.")
    syncSummary: dict | None = Field(default=None, description="Sync attempt totals and recency.")
    conflictsByStatus: dict[str, int] | None = Field(default=None, description="Resolution conflict counts by status.")
    rdfOutboxByStatus: dict[str, int] | None = Field(default=None, description="RDF outbox job counts by status.")
    workerHeartbeatSummary: list[dict] | None = Field(default=None, description="Per worker type heartbeat freshness summary.")
    healthSnapshotSummary: dict | None = Field(default=None, description="Health snapshot counts by health/compat status.")
    operationalState: str | None = Field(default=None, description="Derived operational state: healthy, degraded, or unknown.")


class ImportedRecordResponse(StrictModel):
    canonicalId: str = Field(description="Canonical ID of the imported record.")
    authorityNodeId: str = Field(description="Authority node that owns the imported record.")
    localId: str = Field(description="Authority-local record identifier.")
    version: str = Field(description="Authority-local record version.")
    isAuthoritative: bool = Field(description="Always false for imported records stored on this node.")
    lifecycleState: str = Field(description="Lifecycle state of the imported record as last accepted.")
    payloadDigestSha256: str = Field(description="Digest of the last accepted imported payload.")
    verificationStatus: str | None = Field(default=None, description="Result of signature and digest verification.")
    sourceEventId: str | None = Field(default=None, description="Remote event UUID from which this record was imported.")
    sourceEventPosition: int | None = Field(default=None, description="Remote event position last accepted for this record.")
    sourceSignatureKid: str | None = Field(default=None, description="Remote key identifier used to sign the imported event.")
    lastVerifiedAt: datetime | None = Field(default=None, description="Timestamp at which the imported record was last verified successfully.")


class ImportedRecordListResponse(StrictModel):
    items: list[ImportedRecordResponse] = Field(description="Imported records retained for the selected peer.")
    total: int = Field(description="Total imported records retained for the selected peer.")


class AdminPublishRequest(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "localId": "Demo-License",
                "version": "1",
                "payload": {"licenseId": "Demo-License", "name": "Demo License"},
            }
        },
    )

    localId: str = Field(description="Authority-local identifier to publish as a local authoritative federation record.")
    version: str = Field(description="Authority-local version string to publish.")
    payload: dict[str, Any] = Field(description="Authoritative business payload to wrap and sign for outbound federation.")


class PeerSuspendRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=1024, description="Required operator reason for suspension.")
    suspendedUntil: datetime | None = Field(
        default=None,
        description="Optional timezone-aware suspension end timestamp. Omit for indefinite suspension.",
    )


class PeerResumeRequest(StrictModel):
    reason: str | None = Field(default=None, max_length=1024, description="Optional operator reason for resuming synchronization.")


class PeerCircuitResetRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=1024, description="Required operator reason for resetting peer circuit state.")
    expectedState: Literal["closed", "open", "half_open"] | None = Field(
        default=None,
        description="Optional expected current circuit state for optimistic concurrency.",
    )


class PeerProbeResponse(StrictModel):
    peerId: UUID = Field(description="Local trusted peer UUID.")
    peerNodeId: str = Field(description="Pinned immutable peer node UUID.")
    reachableDiscovery: bool = Field(description="Whether discovery endpoint was reachable and valid.")
    reachableJwks: bool = Field(description="Whether JWKS endpoint was reachable and valid.")
    roundTripMs: int = Field(ge=0, description="Approximate end-to-end probe round-trip time in milliseconds.")
    healthStatus: str = Field(description="Bounded health status.")
    errorCode: str | None = Field(default=None, description="Bounded machine-readable error code, if probe failed.")
    circuitState: Literal["closed", "open", "half_open"] = Field(description="Circuit state after probe transition.")
    sampledAt: datetime = Field(description="Probe sample timestamp.")


class PeerKeyInventoryItem(StrictModel):
    peerId: UUID = Field(description="Local trusted peer UUID.")
    peerNodeId: str = Field(description="Pinned immutable peer node UUID.")
    kid: str = Field(description="Peer public verification key identifier.")
    algorithm: str = Field(description="Verification algorithm.")
    keyType: str = Field(description="JWK key type.")
    curve: str = Field(description="JWK curve.")
    publicFingerprint: str = Field(description="Canonical public-key fingerprint (sha256:<hex>).")
    status: Literal["active", "retired", "revoked"] = Field(description="Current key lifecycle status.")
    validFrom: datetime | None = Field(default=None, description="Server-assigned key validity start timestamp.")
    validUntil: datetime | None = Field(default=None, description="Server-assigned key validity end timestamp.")
    firstSeenAt: datetime = Field(description="Server timestamp when key was first observed/approved.")
    lastSeenAt: datetime = Field(description="Server timestamp when key was last observed.")
    createdAt: datetime = Field(description="Row creation timestamp.")
    updatedAt: datetime = Field(description="Last row update timestamp.")


class PeerKeyInventoryResponse(StrictModel):
    peerId: UUID = Field(description="Local trusted peer UUID.")
    peerNodeId: str = Field(description="Pinned immutable peer node UUID.")
    items: list[PeerKeyInventoryItem] = Field(default_factory=list, description="Stored verification keys for this peer.")


class PeerKeyInspectRequest(StrictModel):
    reason: str | None = Field(default=None, max_length=1024, description="Optional bounded operator reason.")


class PeerKeyDiffItem(StrictModel):
    kid: str | None = Field(default=None, description="Public key identifier when available.")
    publicFingerprint: str | None = Field(default=None, description="Public-key fingerprint (sha256:<hex>) when available.")
    storedStatus: Literal["active", "retired", "revoked"] | None = Field(default=None, description="Stored status when entry exists locally.")
    reasonCode: str = Field(description="Bounded machine-readable category reason.")


class PeerKeyInspectResponse(StrictModel):
    peerId: UUID = Field(description="Local trusted peer UUID.")
    peerNodeId: str = Field(description="Pinned immutable peer node UUID.")
    known: list[PeerKeyDiffItem] = Field(default_factory=list, description="Keys where kid+fingerprint already match stored values.")
    new: list[PeerKeyDiffItem] = Field(default_factory=list, description="Newly observed keys absent from local trusted key set.")
    removed: list[PeerKeyDiffItem] = Field(default_factory=list, description="Locally stored keys absent from remote JWKS.")
    changed: list[PeerKeyDiffItem] = Field(default_factory=list, description="Same kid observed with different fingerprint/public material.")
    invalid: list[PeerKeyDiffItem] = Field(default_factory=list, description="Malformed/unsupported/duplicate/unusable remote keys.")
    expired: list[PeerKeyDiffItem] = Field(default_factory=list, description="Stored keys whose validity boundary has elapsed.")


class PeerKeyApproveRequest(StrictModel):
    kid: str = Field(min_length=1, max_length=128, description="Remote key identifier to approve.")
    expectedFingerprint: str = Field(
        min_length=71,
        max_length=71,
        description="Expected fingerprint in sha256:<lowercase-hex> format.",
        examples=["sha256:c76e746a0f2b78e0bf2ca8f1478b1f087834b23499f9f8e640b8d89cd5233d7a"],
    )
    reason: str = Field(min_length=1, max_length=1024, description="Required bounded operator reason.")


class PeerKeyStatusMutationRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=1024, description="Required bounded operator reason.")
    expectedStatus: Literal["active", "retired", "revoked"] | None = Field(
        default=None,
        description="Optional expected current key status for optimistic concurrency.",
    )
