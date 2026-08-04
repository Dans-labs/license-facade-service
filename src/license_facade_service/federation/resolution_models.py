from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


ResolutionOutcome = Literal["local-authoritative", "imported", "spdx-fallback"]
LifecycleState = Literal["active", "deprecated", "tombstoned"]
ConflictState = Literal["none", "open", "resolved", "dismissed", "superseded", "stale"]
SourceTrustState = Literal["trusted", "revoked", "unknown"]
SourceOperationalState = Literal["enabled", "disabled", "archived"]
SourceAvailability = Literal["online", "offline", "unknown"]
FreshnessState = Literal["fresh", "stale", "unknown"]


class ResolutionLinkSet(BaseModel):
    self: str
    canonical: str
    provenance: str | None = None
    conflict: str | None = None
    resolution: str | None = None
    representation: list[str] = Field(default_factory=list)


class ResolutionFreshness(BaseModel):
    resolvedAt: datetime | None = None
    sourceObservedAt: datetime | None = None
    lastSyncedAt: datetime | None = None
    stale: bool = False


class ResolutionSourceState(BaseModel):
    trustState: SourceTrustState
    operationalState: SourceOperationalState
    availability: SourceAvailability
    peerId: UUID | None = None
    peerNodeId: str | None = None
    sourcePeer: str | None = None


class ProvenanceSummary(BaseModel):
    summary: str
    sourceUri: str | None = None
    sourceDigestSha256: str | None = None
    sourceEventId: UUID | None = None
    sourceEventPosition: int | None = None


class ConflictContextLinkSet(BaseModel):
    self: str
    canonical: str | None = None
    provenance: str | None = None
    resolution: str | None = None


class LicenseResolutionResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    identifier: str
    canonicalId: str | None = None
    authoritativeCanonicalId: str | None = None
    authorityNodeId: str | None = None
    sourcePeerId: UUID | None = None
    sourcePeerNodeId: str | None = None
    recordId: UUID | None = None
    version: str | None = None
    resolutionOutcome: ResolutionOutcome
    lifecycleState: LifecycleState
    conflictState: ConflictState
    sourceTrustState: SourceTrustState
    sourceOperationalState: SourceOperationalState
    sourceAvailability: SourceAvailability
    freshnessState: FreshnessState
    freshness: ResolutionFreshness
    provenance: ProvenanceSummary | None = None
    conflictId: UUID | None = None
    conflictStatus: str | None = None
    conflictDecisionEffectiveness: str | None = None
    resolutionContextId: str | None = None
    links: ResolutionLinkSet = Field(alias="_links")


class ProvenanceEventResponse(BaseModel):
    eventId: UUID
    eventPosition: int
    operation: str
    signedPayloadDigestSha256: str
    generatedAt: datetime
    receivedAt: datetime
    processingStatus: str
    sourcePeerId: UUID | None = None
    sourcePeerNodeId: str | None = None
    authorityNodeId: str | None = None
    canonicalId: str
    payloadDigestSha256: str


class LicenseProvenanceResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    identifier: str
    canonicalId: str | None = None
    recordId: UUID | None = None
    sourcePeerId: UUID | None = None
    authorityNodeId: str | None = None
    lifecycleState: LifecycleState
    provenance: ProvenanceSummary | None = None
    events: list[ProvenanceEventResponse] = Field(default_factory=list)
    links: ResolutionLinkSet = Field(alias="_links")


class ConflictCandidateResponse(BaseModel):
    recordId: UUID | None = None
    canonicalId: str
    authorityNodeId: str | None = None
    sourcePeerId: UUID | None = None
    sourcePeerNodeId: str | None = None
    payloadDigestSha256: str
    version: str | None = None
    lifecycleState: LifecycleState
    sourceTrustState: SourceTrustState
    sourceOperationalState: SourceOperationalState
    sourceAvailability: SourceAvailability
    isLocalAuthoritative: bool = False


class ConflictDecisionResponse(BaseModel):
    conflictId: UUID
    version: int
    status: str
    decisionType: str
    decisionEffectiveness: str
    actorRole: str
    actorIdentifier: str | None = None
    rationale: str | None = None
    beforeState: dict[str, Any] = Field(default_factory=dict)
    afterState: dict[str, Any] = Field(default_factory=dict)
    createdAt: datetime


class ConflictResponse(BaseModel):
    conflictId: UUID
    normalizedIdentifier: str
    conflictType: str
    status: str
    version: int
    decisionEffectiveness: str | None = None
    candidateSummary: list[ConflictCandidateResponse] = Field(default_factory=list)
    decision: ConflictDecisionResponse | None = None
    createdAt: datetime
    updatedAt: datetime
    resolvedAt: datetime | None = None
    reopenedAt: datetime | None = None
    links: ConflictContextLinkSet = Field(alias="_links")


class ConflictDecisionRequest(BaseModel):
    expectedVersion: int
    decisionType: Literal["approve", "dismiss", "reverse", "supersede", "prefer-imported", "acknowledge", "alias-correct"]
    rationale: str | None = None
    aliasValue: str | None = None


class RdfOutboxJobResponse(BaseModel):
    id: UUID
    dedupeKey: str
    jobType: str
    status: str
    recordId: UUID | None = None
    authorityNodeId: str | None = None
    sourcePeerId: UUID | None = None
    graphUri: str
    expectedGeneration: int
    expectedDigestSha256: str
    attemptCount: int
    nextAttemptAt: datetime | None = None
    leasedUntil: datetime | None = None
    lastErrorCode: str | None = None
    lastErrorDetail: str | None = None
    createdAt: datetime
    updatedAt: datetime
    deadLetteredAt: datetime | None = None


class RdfGraphStateResponse(BaseModel):
    graphUri: str
    graphKind: str
    recordId: UUID | None = None
    authorityNodeId: str | None = None
    sourcePeerId: UUID | None = None
    expectedGeneration: int
    expectedDigestSha256: str | None = None
    currentGeneration: int
    currentDigestSha256: str | None = None
    status: str
    lastSuccessAt: datetime | None = None
    lastAttemptAt: datetime | None = None
    lastErrorCode: str | None = None
    lastErrorDetail: str | None = None
    ownedByService: bool = True
