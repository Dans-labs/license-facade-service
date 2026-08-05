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
    self: str = Field(description="Canonical URL of the current response resource.")
    canonical: str = Field(description="Canonical licence lookup URL for the selected identifier.")
    provenance: str | None = Field(default=None, description="Provenance endpoint for the same identifier, when available.")
    conflict: str | None = Field(default=None, description="Conflict review endpoint for the active ambiguity, when applicable.")
    resolution: str | None = Field(default=None, description="Resolution endpoint for the same identifier.")
    representation: list[str] = Field(default_factory=list, description="Useful representation URLs for the selected licence record.")


class ResolutionFreshness(BaseModel):
    resolvedAt: datetime | None = Field(default=None, description="Timestamp at which this node evaluated the identifier.")
    sourceObservedAt: datetime | None = Field(default=None, description="Timestamp at which the selected source record was last observed or published.")
    lastSyncedAt: datetime | None = Field(default=None, description="Timestamp of the last successful synchronization relevant to the selected source.")
    stale: bool = Field(default=False, description="Convenience flag indicating whether the selected source should be treated as stale.")


class ResolutionSourceState(BaseModel):
    trustState: SourceTrustState = Field(description="Trust state applied to the selected imported source.")
    operationalState: SourceOperationalState = Field(description="Operational inclusion state applied to the selected imported source.")
    availability: SourceAvailability = Field(description="Best-known online/offline availability of the selected imported source.")
    peerId: UUID | None = Field(default=None, description="Local trusted-peer UUID for the selected imported source.")
    peerNodeId: str | None = Field(default=None, description="Remote node UUID for the selected imported source.")
    sourcePeer: str | None = Field(default=None, description="Human-readable peer label, when available.")


class ProvenanceSummary(BaseModel):
    summary: str = Field(description="High-level provenance summary for the selected result.")
    sourceUri: str | None = Field(default=None, description="Remote or upstream source URI used for the selected result.")
    sourceDigestSha256: str | None = Field(default=None, description="Digest of the source payload or signed wrapper, when known.")
    sourceEventId: UUID | None = Field(default=None, description="Source federation event UUID, when applicable.")
    sourceEventPosition: int | None = Field(default=None, description="Source federation event position, when applicable.")


class ConflictContextLinkSet(BaseModel):
    self: str = Field(description="Canonical URL of the conflict resource.")
    canonical: str | None = Field(default=None, description="Canonical licence endpoint related to the conflict.")
    provenance: str | None = Field(default=None, description="Provenance endpoint related to the conflict identifier.")
    resolution: str | None = Field(default=None, description="Resolution endpoint related to the conflict identifier.")


class LicenseResolutionResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    identifier: str = Field(description="Identifier exactly as resolved after single URL decoding and normalization.")
    canonicalId: str | None = Field(default=None, description="Canonical identifier selected for the response.")
    authoritativeCanonicalId: str | None = Field(default=None, description="Canonical identifier of the authoritative winner when different lookup aliases were supplied.")
    authorityNodeId: str | None = Field(default=None, description="Authority node UUID for the selected result, when federated data was used.")
    sourcePeerId: UUID | None = Field(default=None, description="Local trusted-peer UUID that supplied the selected imported record, when applicable.")
    sourcePeerNodeId: str | None = Field(default=None, description="Remote peer node UUID that supplied the selected imported record, when applicable.")
    recordId: UUID | None = Field(default=None, description="Local PostgreSQL record UUID for the selected result, when available.")
    version: str | None = Field(default=None, description="Authority-local version of the selected result, when available.")
    resolutionOutcome: ResolutionOutcome = Field(description="How the identifier was satisfied: local authoritative, imported, or SPDX fallback.")
    lifecycleState: LifecycleState = Field(description="Lifecycle state of the selected identity.")
    conflictState: ConflictState = Field(description="Conflict state relevant to this identifier at resolution time.")
    sourceTrustState: SourceTrustState = Field(description="Trust state of the selected source.")
    sourceOperationalState: SourceOperationalState = Field(description="Operational inclusion state of the selected source.")
    sourceAvailability: SourceAvailability = Field(description="Best-known online/offline availability of the selected source.")
    freshnessState: FreshnessState = Field(description="Freshness classification used for the selected result.")
    freshness: ResolutionFreshness = Field(description="Timestamps and convenience flags explaining the freshness decision.")
    provenance: ProvenanceSummary | None = Field(default=None, description="High-level provenance summary for the selected result.")
    conflictId: UUID | None = Field(default=None, description="Conflict UUID responsible for a conflicted or ambiguous result, when applicable.")
    conflictStatus: str | None = Field(default=None, description="Current conflict record status, when applicable.")
    conflictDecisionEffectiveness: str | None = Field(default=None, description="Effectiveness of the current conflict decision, when applicable.")
    resolutionContextId: str | None = Field(default=None, description="Implementation-specific context identifier, when available.")
    links: ResolutionLinkSet = Field(alias="_links", description="Related links for the same identity and any associated conflict.")


class ProvenanceEventResponse(BaseModel):
    eventId: UUID = Field(description="Locally stored provenance-event UUID.")
    eventPosition: int = Field(description="Remote event position accepted for this provenance entry.")
    operation: str = Field(description="Lifecycle operation represented by the provenance event.")
    signedPayloadDigestSha256: str = Field(description="Digest of the signed source payload associated with the provenance event.")
    generatedAt: datetime = Field(description="Timestamp at which the source event was generated.")
    receivedAt: datetime = Field(description="Timestamp at which this node received or asserted the provenance event.")
    processingStatus: str = Field(description="Processing result recorded for this provenance entry.")
    sourcePeerId: UUID | None = Field(default=None, description="Local trusted-peer UUID that supplied this event.")
    sourcePeerNodeId: str | None = Field(default=None, description="Remote peer node UUID that supplied this event.")
    authorityNodeId: str | None = Field(default=None, description="Authority node UUID for the event payload.")
    canonicalId: str = Field(description="Canonical ID associated with the provenance event.")
    payloadDigestSha256: str = Field(description="Digest of the imported record payload associated with this event.")


class LicenseProvenanceResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    identifier: str = Field(description="Identifier exactly as resolved after single URL decoding and normalization.")
    canonicalId: str | None = Field(default=None, description="Canonical identifier selected for the provenance response.")
    recordId: UUID | None = Field(default=None, description="Local PostgreSQL record UUID, when available.")
    sourcePeerId: UUID | None = Field(default=None, description="Local trusted-peer UUID that supplied the selected imported record, when applicable.")
    authorityNodeId: str | None = Field(default=None, description="Authority node UUID for the selected result, when federated data was used.")
    lifecycleState: LifecycleState = Field(description="Lifecycle state of the selected record.")
    provenance: ProvenanceSummary | None = Field(default=None, description="High-level provenance summary for the selected result.")
    events: list[ProvenanceEventResponse] = Field(default_factory=list, description="Ordered signed provenance history retained for the selected result.")
    links: ResolutionLinkSet = Field(alias="_links", description="Related resolution, provenance, and representation links.")


class ConflictCandidateResponse(BaseModel):
    recordId: UUID | None = Field(default=None, description="Local PostgreSQL record UUID for this candidate, when available.")
    canonicalId: str = Field(description="Canonical identifier for this candidate.")
    authorityNodeId: str | None = Field(default=None, description="Authority node UUID for this candidate.")
    sourcePeerId: UUID | None = Field(default=None, description="Local trusted-peer UUID that supplied this imported candidate, when applicable.")
    sourcePeerNodeId: str | None = Field(default=None, description="Remote node UUID that supplied this imported candidate, when applicable.")
    payloadDigestSha256: str = Field(description="Digest of the candidate payload used for auditing and comparison.")
    version: str | None = Field(default=None, description="Authority-local version string for this candidate.")
    lifecycleState: LifecycleState = Field(description="Lifecycle state of this candidate.")
    sourceTrustState: SourceTrustState = Field(description="Trust state of the candidate source.")
    sourceOperationalState: SourceOperationalState = Field(description="Operational state of the candidate source.")
    sourceAvailability: SourceAvailability = Field(description="Availability state of the candidate source.")
    isLocalAuthoritative: bool = Field(default=False, description="Whether this candidate is the local authoritative record.")


class ConflictDecisionResponse(BaseModel):
    conflictId: UUID = Field(description="Conflict UUID that this decision event belongs to.")
    version: int = Field(description="Append-only conflict-decision event version.")
    status: str = Field(description="Current conflict status after this decision event.")
    decisionType: str = Field(description="Decision event type recorded for the conflict.")
    decisionEffectiveness: str = Field(description="Whether this decision is current, reversed, stale, or superseded.")
    actorRole: str = Field(description="Role that recorded the decision event.")
    actorIdentifier: str | None = Field(default=None, description="Optional actor identifier recorded with the decision event.")
    rationale: str | None = Field(default=None, description="Human rationale recorded for the decision event.")
    beforeState: dict[str, Any] = Field(default_factory=dict, description="Conflict state snapshot before this decision event.")
    afterState: dict[str, Any] = Field(default_factory=dict, description="Conflict state snapshot after this decision event.")
    createdAt: datetime = Field(description="Timestamp at which the decision event was recorded.")


class ConflictResponse(BaseModel):
    conflictId: UUID = Field(description="Conflict UUID used for review and decision APIs.")
    normalizedIdentifier: str = Field(description="Normalized identifier that produced the conflict.")
    conflictType: str = Field(description="Conflict category, for example imported ambiguity or alias collision.")
    status: str = Field(description="Current conflict status.")
    version: int = Field(description="Current optimistic-concurrency version of the conflict record.")
    decisionEffectiveness: str | None = Field(default=None, description="Effectiveness of the latest decision, when one exists.")
    candidateSummary: list[ConflictCandidateResponse] = Field(default_factory=list, description="Candidates currently participating in the conflict.")
    decision: ConflictDecisionResponse | None = Field(default=None, description="Latest decision event associated with the conflict, when present.")
    createdAt: datetime = Field(description="Timestamp at which the conflict record was created.")
    updatedAt: datetime = Field(description="Timestamp at which the conflict record was last updated.")
    resolvedAt: datetime | None = Field(default=None, description="Timestamp at which the conflict was resolved, when applicable.")
    reopenedAt: datetime | None = Field(default=None, description="Timestamp at which the conflict was reopened after reversal, when applicable.")
    links: ConflictContextLinkSet = Field(alias="_links", description="Related links for conflict review, provenance, and resolution.")


class ConflictDecisionRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "expectedVersion": 3,
                "decisionType": "prefer-imported",
                "rationale": "Prefer peer A until the duplicate imported alias is reviewed.",
                "aliasValue": "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:Demo-License:1",
            }
        }
    )

    expectedVersion: int = Field(description="Optimistic-concurrency version expected by the caller. Requests against stale versions fail with 409.")
    decisionType: Literal["approve", "dismiss", "reverse", "supersede", "prefer-imported", "acknowledge", "alias-correct"] = Field(
        description="Append-only decision event type to record for the conflict.",
    )
    rationale: str | None = Field(default=None, description="Optional human rationale stored with the decision event.")
    aliasValue: str | None = Field(default=None, description="Optional candidate canonical ID or alias correction value required by some decision types.")


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
