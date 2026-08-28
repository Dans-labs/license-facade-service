from __future__ import annotations

import hashlib
import hmac
import logging
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationConflictRecord,
    FederationInboundEvent,
    FederationPeerAuditLog,
    FederationPeerCursor,
    FederationPeerHealthSnapshot,
    FederationPeerSigningKey,
    FederationRecord,
    FederationRecordProvenance,
    FederationResolutionAlias,
    FederationSyncAttempt,
    FederationTrustedPeer,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import canonical_json_sha256_hex, sha256_hex
from src.license_facade_service.federation.inbound_models import (
    AdminStatusResponse,
    ImportedRecordListResponse,
    ImportedRecordResponse,
    PeerKeyDiffItem,
    PeerKeyInspectResponse,
    PeerKeyInventoryItem,
    PeerKeyInventoryResponse,
    PeerCreateRequest,
    PeerPatchRequest,
    PeerResponse,
    RemoteChangesResponse,
    RemoteDiscoveryResponse,
    RemoteJwksResponse,
    RemoteRecordResponse,
    SyncResultResponse,
)
from src.license_facade_service.federation.audit import (
    AuditAction,
    AuditActorType,
    AuditDetailBuilder,
    AuditOutcome,
    AuditTargetType,
    CircuitState,
    sanitize_free_text,
    write_audit_row_sync,
)
from src.license_facade_service.federation.circuit import PeerCircuitService
from src.license_facade_service.federation.json_strict import DuplicateJsonKeyError, loads_json_no_duplicates
from src.license_facade_service.federation.lease import ClaimedLease, LeaseConflictError, SyncLeaseRepository
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.outbound import FederationError, encode_canonical_id
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService
from src.license_facade_service.federation.security import FederationUrlPolicy, UrlSecurityError

logger = logging.getLogger(__name__)

_HEALTH_ERROR_SUMMARIES: dict[str, str] = {
    "remote-unreachable": "Remote peer is unreachable.",
    "remote-tls-error": "TLS connection to remote peer failed.",
    "remote-server-error": "Remote peer returned a server error.",
    "remote-http-error": "Remote peer returned a request error.",
    "peer-node-mismatch": "Remote peer identity did not match pinned identity.",
    "peer-base-url-mismatch": "Remote peer base URL did not match pinned identity.",
    "peer-key-missing": "Pinned peer signing key is no longer advertised.",
    "unknown-signing-key": "Remote event used an unapproved signing key.",
    "retired-signing-key": "Remote event used a retired signing key.",
    "revoked-signing-key": "Remote event used a revoked signing key.",
    "signing-key-not-yet-valid": "Remote event used a key that is not yet valid.",
    "signing-key-expired": "Remote event used an expired signing key.",
    "invalid-signature-alg": "Remote signature validation failed.",
    "invalid-signature": "Remote signature validation failed.",
    "digest-mismatch": "Remote signature validation failed.",
    "record-payload-digest-mismatch": "Remote signature validation failed.",
    "event-id-collision": "Remote event integrity validation failed.",
    "event-position-collision": "Remote event integrity validation failed.",
    "event-replay-mismatch": "Remote event integrity validation failed.",
    "sync-timeout": "Federation synchronization timed out.",
}


def _safe_health_error_detail(error: FederationError) -> str:
    if error.code in _HEALTH_ERROR_SUMMARIES:
        return _HEALTH_ERROR_SUMMARIES[error.code]
    return sanitize_free_text("Federation operation failed.", max_len=256)


def ed25519_key_fingerprint_hex(x_b64url: str) -> str:
    raw = _b64url_decode(x_b64url)
    if len(raw) != 32:
        raise FederationError("invalid-peer-key", "Peer key length is invalid for Ed25519.")
    return hashlib.sha256(raw).hexdigest()


def _b64url_decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class PeerKeyVerificationPurpose(str, Enum):
    NEW_INBOUND_EVENT = "NEW_INBOUND_EVENT"
    HISTORICAL_EVIDENCE = "HISTORICAL_EVIDENCE"


@dataclass(frozen=True)
class PeerKeyVerificationResult:
    signature_valid: bool
    key_found: bool
    trust_status: str
    eligible_for_application: bool
    rejection_reason: str | None


@dataclass(frozen=True)
class _HttpLimits:
    max_bytes: int
    expected_content_type: str


class FederationRemoteClient:
    """
    DNS rebinding note:
    We re-resolve and validate all DNS answers before every request and reject unsafe targets.
    The default HTTP client stack may still perform its own DNS resolution before connect.
    Production deployments must enforce egress network policy to trusted destinations.
    """

    def __init__(
        self,
        settings: FederationSettings,
        *,
        http_client: httpx.Client | None = None,
        url_policy: FederationUrlPolicy | None = None,
    ):
        self.settings = settings
        self.url_policy = url_policy or FederationUrlPolicy(settings)
        self.http_client = http_client or httpx.Client(
            timeout=httpx.Timeout(
                connect=settings.sync_connect_timeout_seconds,
                read=settings.sync_read_timeout_seconds,
                write=settings.sync_write_timeout_seconds,
                pool=settings.sync_pool_timeout_seconds,
            ),
            follow_redirects=False,
        )

    def get_json(
        self,
        url: str,
        *,
        limits: _HttpLimits,
        allowed_hostnames: tuple[str, ...] = (),
        allowed_cidrs: tuple[str, ...] = (),
    ) -> Any:
        attempts = max(1, self.settings.sync_retry_attempts)
        for attempt in range(attempts):
            try:
                self.url_policy.validate_and_resolve(
                    url,
                    allowed_hostnames=allowed_hostnames,
                    allowed_cidrs=allowed_cidrs,
                )
                with self.http_client.stream("GET", url, headers={"Accept": limits.expected_content_type}) as response:
                    if 300 <= response.status_code <= 399:
                        location = response.headers.get("location")
                        if location:
                            try:
                                self.url_policy.validate_and_resolve(
                                    location,
                                    allowed_hostnames=allowed_hostnames,
                                    allowed_cidrs=allowed_cidrs,
                                )
                            except UrlSecurityError:
                                pass
                        raise FederationError("remote-redirect", "Remote redirects are not allowed.")
                    if response.status_code >= 500:
                        if attempt + 1 < attempts:
                            time.sleep(min(self.settings.sync_retry_base_seconds * (2**attempt), self.settings.sync_retry_max_seconds) + random.uniform(0, 0.1))
                            continue
                        raise FederationError("remote-server-error", f"Remote endpoint returned HTTP {response.status_code}.")
                    if response.status_code >= 400:
                        raise FederationError("remote-http-error", f"Remote endpoint returned HTTP {response.status_code}.")
                    content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
                    if content_type != limits.expected_content_type:
                        raise FederationError("remote-content-type", "Remote endpoint returned unexpected content type.")
                    length = response.headers.get("content-length")
                    content_length: int | None = None
                    if length is not None:
                        try:
                            content_length = int(length)
                        except ValueError as exc:
                            raise FederationError("remote-response-size", "Remote Content-Length header is invalid.") from exc
                        if content_length < 0:
                            raise FederationError("remote-response-size", "Remote Content-Length header is invalid.")
                        if content_length > limits.max_bytes:
                            raise FederationError("remote-payload-too-large", "Remote payload is too large.")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > limits.max_bytes:
                            raise FederationError("remote-payload-too-large", "Remote payload is too large.")
                    if content_length is not None and len(body) != content_length:
                        raise FederationError("remote-response-size", "Remote response size does not match Content-Length.")
                    try:
                        return loads_json_no_duplicates(bytes(body))
                    except DuplicateJsonKeyError as exc:
                        raise FederationError("duplicate-json-key", str(exc)) from exc
                    except Exception as exc:
                        raise FederationError("invalid-remote-json", "Remote JSON is malformed.") from exc
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if isinstance(exc, httpx.TransportError):
                    msg = str(exc).lower()
                    if any(token in msg for token in ("tls", "ssl", "certificate", "cert verify")):
                        raise FederationError("remote-tls-error", "Remote TLS validation failed.") from exc
                if attempt + 1 < attempts:
                    time.sleep(min(self.settings.sync_retry_base_seconds * (2**attempt), self.settings.sync_retry_max_seconds) + random.uniform(0, 0.1))
                    continue
                raise FederationError("remote-unreachable", "Remote endpoint is unreachable.") from exc
        raise FederationError("remote-unreachable", "Remote endpoint is unreachable.")


class FederationPeerService:
    def __init__(
        self,
        db: Database,
        settings: FederationSettings,
        remote_client: FederationRemoteClient | None = None,
        *,
        owner_instance_id: uuid.UUID | None = None,
        now_provider: Callable[[], datetime] | None = None,
        jitter_provider: Callable[[], float] | None = None,
    ):
        self.db = db
        self.settings = settings
        self.remote_client = remote_client or FederationRemoteClient(settings)
        self.owner_instance_id = owner_instance_id or uuid.uuid4()
        self.lease_repo = SyncLeaseRepository()
        self.circuit = PeerCircuitService(
            settings,
            now_provider=now_provider or (lambda: datetime.now(timezone.utc)),
            jitter_provider=jitter_provider or (lambda: random.uniform(0.75, 1.25)),
        )

    def _combined_allowlists(
        self,
        *,
        peer_allowed_hostnames: str | None = None,
        peer_allowed_cidrs: str | None = None,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        hostnames = tuple(
            item
            for item in list(self.settings.sync_allowed_hostnames) + list(self._split_csv(peer_allowed_hostnames))
            if item
        )
        cidrs = tuple(
            item for item in list(self.settings.sync_allowed_cidrs) + list(self._split_csv(peer_allowed_cidrs)) if item
        )
        return hostnames, cidrs

    @staticmethod
    def _split_csv(raw: str | None) -> tuple[str, ...]:
        if not raw:
            return ()
        return tuple(item.strip() for item in raw.split(",") if item.strip())

    @staticmethod
    def _fingerprint_with_prefix(raw_hex: str) -> str:
        return f"sha256:{raw_hex.lower()}"

    @staticmethod
    def _normalize_expected_fingerprint(value: str) -> str:
        text = (value or "").strip().lower()
        if len(text) != 71 or not text.startswith("sha256:"):
            raise FederationError("peer-key-fingerprint-invalid", "expectedFingerprint must use sha256:<lowercase-hex> format.")
        digest = text[7:]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise FederationError("peer-key-fingerprint-invalid", "expectedFingerprint must use sha256:<lowercase-hex> format.")
        return text

    @staticmethod
    def _remote_key_from_mapping(item: dict[str, Any]) -> tuple[str, str] | tuple[None, str]:
        kid = item.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            return None, "missing-kid"
        alg = item.get("alg")
        if alg != "EdDSA":
            return None, "unsupported-algorithm"
        kty = item.get("kty")
        if kty != "OKP":
            return None, "unsupported-kty"
        crv = item.get("crv")
        if crv != "Ed25519":
            return None, "unsupported-curve"
        x = item.get("x")
        if not isinstance(x, str) or not x.strip():
            return None, "missing-public-key"
        return kid.strip(), x

    def _fetch_and_validate_peer_snapshot(
        self,
        *,
        base_url: str,
        allow_private_network: bool,
        expected_node_id: str,
        allowed_hostnames: tuple[str, ...],
        allowed_cidrs: tuple[str, ...],
    ) -> tuple[RemoteDiscoveryResponse, RemoteJwksResponse]:
        discovery = self._fetch_discovery(
            base_url,
            allow_private_network=allow_private_network,
            allowed_hostnames=allowed_hostnames,
            allowed_cidrs=allowed_cidrs,
        )
        if discovery.nodeId != expected_node_id:
            raise FederationError("peer-node-mismatch", "Discovery nodeId does not match requested peerNodeId.")
        if discovery.publicBaseUrl.rstrip("/") != base_url.rstrip("/"):
            raise FederationError("peer-base-url-mismatch", "Discovery publicBaseUrl does not match expected base URL.")
        jwks = self._fetch_jwks(
            discovery.jwksUrl,
            allow_private_network=allow_private_network,
            allowed_hostnames=allowed_hostnames,
            allowed_cidrs=allowed_cidrs,
        )
        return discovery, jwks

    def list_peers(self, *, limit: int, offset: int) -> tuple[list[PeerResponse], int]:
        with self.db.transaction() as session:
            total = int(session.execute(select(func.count()).select_from(FederationTrustedPeer)).scalar_one())
            rows = (
                session.execute(select(FederationTrustedPeer).order_by(FederationTrustedPeer.created_at).limit(limit).offset(offset))
                .scalars()
                .all()
            )
            # Fetch latest health snapshot per peer (avoid N+1)
            peer_ids = [r.id for r in rows]
            health_by_peer: dict[uuid.UUID, dict] = {}
            if peer_ids:
                from sqlalchemy import and_, func as sqlfunc
                from sqlalchemy.dialects.postgresql import UUID as PG_UUID

                # Use a subquery to get the latest sampled_at per peer_id
                latest_ts_subq = (
                    select(
                        FederationPeerHealthSnapshot.peer_id,
                        sqlfunc.max(FederationPeerHealthSnapshot.sampled_at).label("max_sampled_at"),
                    )
                    .where(FederationPeerHealthSnapshot.peer_id.in_(peer_ids))
                    .group_by(FederationPeerHealthSnapshot.peer_id)
                    .subquery()
                )
                latest_snaps = session.execute(
                    select(FederationPeerHealthSnapshot).join(
                        latest_ts_subq,
                        and_(
                            FederationPeerHealthSnapshot.peer_id == latest_ts_subq.c.peer_id,
                            FederationPeerHealthSnapshot.sampled_at == latest_ts_subq.c.max_sampled_at,
                        ),
                    )
                ).scalars().all()
                for snap in latest_snaps:
                    if snap.peer_id not in health_by_peer:
                        health_by_peer[snap.peer_id] = {
                            "health_status": snap.health_status,
                            "compatibility_status": snap.compatibility_status,
                        }
        return [self._to_peer_response(row, health_by_peer.get(row.id)) for row in rows], total

    def get_peer(self, peer_id: uuid.UUID) -> PeerResponse:
        with self.db.transaction() as session:
            row = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if row is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            # Get latest health snapshot for this peer
            latest_snap = session.execute(
                select(FederationPeerHealthSnapshot)
                .where(FederationPeerHealthSnapshot.peer_id == peer_id)
                .order_by(FederationPeerHealthSnapshot.sampled_at.desc(), FederationPeerHealthSnapshot.id.desc())
                .limit(1)
            ).scalar_one_or_none()
            latest_health = (
                {"health_status": latest_snap.health_status, "compatibility_status": latest_snap.compatibility_status}
                if latest_snap else None
            )
        return self._to_peer_response(row, latest_health)

    def list_imported_records(self, peer_id: uuid.UUID) -> ImportedRecordListResponse:
        with self.db.transaction() as session:
            peer = session.execute(
                select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
            ).scalar_one_or_none()
            if peer is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            records = (
                session.execute(
                    select(FederationRecord).where(
                        FederationRecord.imported_from_peer_id == peer_id,
                        FederationRecord.is_authoritative.is_(False),
                    )
                )
                .scalars()
                .all()
            )
        items = [
            ImportedRecordResponse(
                canonicalId=row.canonical_id,
                authorityNodeId=row.authority_node_id,
                localId=row.local_id,
                version=row.version,
                isAuthoritative=row.is_authoritative,
                lifecycleState=row.lifecycle_state,
                payloadDigestSha256=row.payload_digest_sha256,
                verificationStatus=row.verification_status,
                sourceEventId=str(row.source_event_id) if row.source_event_id else None,
                sourceEventPosition=row.source_event_position,
                sourceSignatureKid=row.source_signature_kid,
                lastVerifiedAt=row.last_verified_at,
            )
            for row in records
        ]
        return ImportedRecordListResponse(items=items, total=len(items))

    def _to_peer_key_inventory_item(self, *, peer: FederationTrustedPeer, key: FederationPeerSigningKey) -> PeerKeyInventoryItem:
        return PeerKeyInventoryItem(
            peerId=peer.id,
            peerNodeId=peer.peer_node_id,
            kid=key.kid,
            algorithm=key.alg,
            keyType=key.kty,
            curve=key.crv,
            publicFingerprint=self._fingerprint_with_prefix(key.key_fingerprint),
            status=key.key_status,
            validFrom=key.valid_from,
            validUntil=key.valid_until,
            firstSeenAt=key.first_seen_at,
            lastSeenAt=key.last_seen_at,
            createdAt=key.created_at,
            updatedAt=key.updated_at,
        )

    def list_peer_keys(self, *, peer_id: uuid.UUID) -> PeerKeyInventoryResponse:
        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            keys = (
                session.execute(
                    select(FederationPeerSigningKey)
                    .where(FederationPeerSigningKey.peer_id == peer_id)
                    .order_by(FederationPeerSigningKey.kid, FederationPeerSigningKey.created_at)
                )
                .scalars()
                .all()
            )
        return PeerKeyInventoryResponse(
            peerId=peer.id,
            peerNodeId=peer.peer_node_id,
            items=[self._to_peer_key_inventory_item(peer=peer, key=row) for row in keys],
        )

    def inspect_peer_keys(self, *, peer_id: uuid.UUID, reason: str | None, actor: str) -> PeerKeyInspectResponse:
        lease = self._claim_lease(peer_id=peer_id, trigger_type="probe")
        if lease is None:
            raise FederationError("already-running", "Synchronization already running for this peer.")
        try:
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                if peer.archived_at is not None:
                    raise FederationError("peer-archived", "Peer is archived.")
                if peer.trust_status != "trusted":
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
                base_url = peer.base_url
                expected_node_id = peer.peer_node_id
                allow_private_network = peer.allow_private_network
                allowed_hostnames, allowed_cidrs = self._combined_allowlists(
                    peer_allowed_hostnames=peer.allowed_hostnames,
                    peer_allowed_cidrs=peer.allowed_cidrs,
                )

            discovery = self._fetch_discovery(
                base_url,
                allow_private_network=allow_private_network,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
            if discovery.nodeId != expected_node_id:
                raise FederationError("peer-node-mismatch", "Discovery nodeId does not match requested peerNodeId.")
            if discovery.publicBaseUrl.rstrip("/") != base_url.rstrip("/"):
                raise FederationError("peer-base-url-mismatch", "Discovery publicBaseUrl does not match expected base URL.")

            raw_jwks = self.remote_client.get_json(
                discovery.jwksUrl,
                limits=_HttpLimits(self.settings.sync_max_jwks_bytes, "application/jwk-set+json"),
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
            if not isinstance(raw_jwks, dict) or not isinstance(raw_jwks.get("keys"), list):
                raise FederationError("remote-schema-invalid", "Remote JWKS response failed validation.")
            raw_keys = raw_jwks.get("keys", [])
            if len(raw_keys) > self.settings.sync_max_jwks_keys:
                raise FederationError("peer-jwks-too-many-keys", "Peer JWKS key count exceeds configured maximum.")

            invalid_by_kid: dict[str, str] = {}
            invalid_without_kid: list[str] = []
            candidates: list[tuple[str, str]] = []
            for raw_item in raw_keys:
                if not isinstance(raw_item, dict):
                    invalid_without_kid.append("malformed-key")
                    continue
                kid, result = self._remote_key_from_mapping(raw_item)
                if kid is None:
                    invalid_without_kid.append(result)
                    continue
                candidates.append((kid, result))

            kid_counts: dict[str, int] = {}
            for kid, _x in candidates:
                kid_counts[kid] = kid_counts.get(kid, 0) + 1
            valid_remote: dict[str, str] = {}
            for kid, x in candidates:
                if kid_counts[kid] > 1:
                    invalid_by_kid[kid] = "duplicate-kid"
                    continue
                try:
                    fingerprint = ed25519_key_fingerprint_hex(x)
                except FederationError:
                    invalid_by_kid[kid] = "invalid-public-key"
                    continue
                valid_remote[kid] = fingerprint

            with self.db.transaction() as session:
                db_now = session.execute(select(func.now())).scalar_one()
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                stored = (
                    session.execute(select(FederationPeerSigningKey).where(FederationPeerSigningKey.peer_id == peer_id))
                    .scalars()
                    .all()
                )
                stored_by_kid = {row.kid: row for row in stored}
                remote_seen_kids = set(valid_remote.keys()) | set(invalid_by_kid.keys())

                known: list[PeerKeyDiffItem] = []
                new: list[PeerKeyDiffItem] = []
                changed: list[PeerKeyDiffItem] = []
                removed: list[PeerKeyDiffItem] = []
                invalid: list[PeerKeyDiffItem] = []
                expired: list[PeerKeyDiffItem] = []

                for reason_code in invalid_without_kid:
                    invalid.append(
                        PeerKeyDiffItem(
                            kid=None,
                            publicFingerprint=None,
                            storedStatus=None,
                            reasonCode=reason_code,
                        )
                    )

                # Deterministic primary category precedence:
                # invalid -> changed -> expired -> known/new/removed.
                for row in sorted(stored, key=lambda item: (item.kid, item.created_at)):
                    if row.kid in invalid_by_kid:
                        invalid.append(
                            PeerKeyDiffItem(
                                kid=row.kid,
                                publicFingerprint=self._fingerprint_with_prefix(row.key_fingerprint),
                                storedStatus=row.key_status,
                                reasonCode=invalid_by_kid[row.kid],
                            )
                        )
                        continue
                    if row.kid in valid_remote and row.key_fingerprint != valid_remote[row.kid]:
                        changed.append(
                            PeerKeyDiffItem(
                                kid=row.kid,
                                publicFingerprint=self._fingerprint_with_prefix(valid_remote[row.kid]),
                                storedStatus=row.key_status,
                                reasonCode="same-kid-different-material",
                            )
                        )
                        continue
                    if row.valid_until is not None and row.valid_until <= db_now:
                        expired.append(
                            PeerKeyDiffItem(
                                kid=row.kid,
                                publicFingerprint=self._fingerprint_with_prefix(row.key_fingerprint),
                                storedStatus=row.key_status,
                                reasonCode="stored-validity-expired",
                            )
                        )
                        continue
                    if row.kid in valid_remote and row.key_fingerprint == valid_remote[row.kid]:
                        known.append(
                            PeerKeyDiffItem(
                                kid=row.kid,
                                publicFingerprint=self._fingerprint_with_prefix(row.key_fingerprint),
                                storedStatus=row.key_status,
                                reasonCode="known-key",
                            )
                        )
                        continue
                    if row.key_status in {"active", "retired"} and row.kid not in remote_seen_kids:
                        removed.append(
                            PeerKeyDiffItem(
                                kid=row.kid,
                                publicFingerprint=self._fingerprint_with_prefix(row.key_fingerprint),
                                storedStatus=row.key_status,
                                reasonCode="missing-from-remote",
                            )
                        )

                for kid, reason_code in invalid_by_kid.items():
                    if kid in stored_by_kid:
                        continue
                    invalid.append(
                        PeerKeyDiffItem(
                            kid=kid,
                            publicFingerprint=None,
                            storedStatus=None,
                            reasonCode=reason_code,
                        )
                    )

                for kid, remote_fingerprint in sorted(valid_remote.items()):
                    if kid in stored_by_kid:
                        continue
                    new.append(
                        PeerKeyDiffItem(
                            kid=kid,
                            publicFingerprint=self._fingerprint_with_prefix(remote_fingerprint),
                            storedStatus=None,
                            reasonCode="new-key",
                        )
                    )

                key_fn = lambda item: ((item.kid or ""), (item.publicFingerprint or ""), item.reasonCode)
                known.sort(key=key_fn)
                new.sort(key=key_fn)
                removed.sort(key=key_fn)
                changed.sort(key=key_fn)
                invalid.sort(key=key_fn)
                expired.sort(key=key_fn)

                self._write_operational_audit(
                    action=AuditAction.PEER_KEY_INSPECT,
                    peer_id=peer_id,
                    target_type=AuditTargetType.PEER_KEY,
                    target_id=str(peer_id),
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor,
                    reason=reason[:1024] if reason else None,
                    details={
                        "known": len(known),
                        "new": len(new),
                        "removed": len(removed),
                        "changed": len(changed),
                        "invalid": len(invalid),
                        "expired": len(expired),
                    },
                    session=session,
                )
            return PeerKeyInspectResponse(
                peerId=peer_id,
                peerNodeId=expected_node_id,
                known=known,
                new=new,
                removed=removed,
                changed=changed,
                invalid=invalid,
                expired=expired,
            )
        except FederationError as exc:
            if exc.code != "peer-not-found":
                with self.db.transaction() as session:
                    peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                    if peer is not None:
                        self._write_operational_audit(
                            action=AuditAction.PEER_KEY_INSPECT,
                            peer_id=peer_id,
                            target_type=AuditTargetType.PEER_KEY,
                            target_id=str(peer_id),
                            outcome=AuditOutcome.FAILED,
                            actor_id=actor,
                            reason=exc.code,
                            details={"errorCode": exc.code},
                            session=session,
                        )
            raise
        finally:
            try:
                self._release_lease(lease)
            except Exception:
                logger.exception("Failed to release inspect lease for peer %s", peer_id)

    def approve_peer_key(self, *, peer_id: uuid.UUID, kid: str, expected_fingerprint: str, reason: str, actor: str) -> PeerKeyInventoryItem:
        normalized_fingerprint = self._normalize_expected_fingerprint(expected_fingerprint)
        lease = self._claim_lease(peer_id=peer_id, trigger_type="manual")
        if lease is None:
            raise FederationError("already-running", "Synchronization already running for this peer.")
        try:
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                if peer.archived_at is not None:
                    raise FederationError("peer-archived", "Peer is archived.")
                if peer.trust_status != "trusted":
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
                base_url = peer.base_url
                expected_node_id = peer.peer_node_id
                allow_private_network = peer.allow_private_network
                allowed_hostnames, allowed_cidrs = self._combined_allowlists(
                    peer_allowed_hostnames=peer.allowed_hostnames,
                    peer_allowed_cidrs=peer.allowed_cidrs,
                )

            discovery, jwks = self._fetch_and_validate_peer_snapshot(
                base_url=base_url,
                allow_private_network=allow_private_network,
                expected_node_id=expected_node_id,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
            matches = [item for item in jwks.keys if item.kid == kid]
            if not matches:
                raise FederationError("peer-key-not-found", "Requested key kid was not found in peer JWKS.")
            if len(matches) > 1:
                raise FederationError("peer-key-invalid-remote", "Remote JWKS contains duplicate key identifiers.")
            remote_key = matches[0]
            actual_fingerprint = self._fingerprint_with_prefix(ed25519_key_fingerprint_hex(remote_key.x))
            if not hmac.compare_digest(actual_fingerprint, normalized_fingerprint):
                raise FederationError("peer-key-fingerprint-mismatch", "Expected fingerprint does not match remote key material.")

            now = datetime.now(timezone.utc)
            collision_error: FederationError | None = None
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                if peer.archived_at is not None:
                    raise FederationError("peer-archived", "Peer is archived.")
                if peer.trust_status != "trusted":
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
                if peer.peer_node_id != expected_node_id or peer.base_url.rstrip("/") != base_url.rstrip("/") or peer.jwks_url != discovery.jwksUrl:
                    raise FederationError("peer-state-stale", "Peer identity changed during key approval.")
                existing = session.execute(
                    select(FederationPeerSigningKey)
                    .where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.kid == kid,
                    )
                    .with_for_update()
                ).scalar_one_or_none()
                if existing is None:
                    existing = FederationPeerSigningKey(
                        id=uuid.uuid4(),
                        peer_id=peer_id,
                        kid=kid,
                        alg=remote_key.alg,
                        kty=remote_key.kty,
                        crv=remote_key.crv,
                        x=remote_key.x,
                        key_fingerprint=actual_fingerprint[7:],
                        key_status="active",
                        first_seen_at=now,
                        last_seen_at=now,
                        valid_from=now,
                        valid_until=None,
                        approved_by=actor[:128],
                        approved_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(existing)
                    status_detail = "approved"
                elif existing.key_fingerprint == actual_fingerprint[7:]:
                    if existing.key_status == "active":
                        existing.last_seen_at = now
                        existing.approved_by = actor[:128]
                        existing.approved_at = now
                        existing.updated_at = now
                        status_detail = "idempotent-active"
                    else:
                        raise FederationError("peer-key-status-conflict", "Retired or revoked key cannot be reactivated by approval.")
                else:
                    previous_state = peer.circuit_state
                    self.circuit.mark_failure(
                        peer,
                        classification=self.circuit.classify_failure(FederationError("key-collision", "same kid different material"), phase="jwks"),
                    )
                    self._write_operational_audit(
                        action=AuditAction.PEER_KEY_COLLISION_REJECTED,
                        peer_id=peer_id,
                        target_type=AuditTargetType.PEER_KEY,
                        target_id=kid,
                        outcome=AuditOutcome.REJECTED,
                        actor_id=actor,
                        reason="key-collision",
                        details={"kid": kid, "storedStatus": existing.key_status},
                        session=session,
                    )
                    if previous_state != CircuitState.OPEN.value and peer.circuit_state == CircuitState.OPEN.value:
                        self._write_operational_audit(
                            action=AuditAction.SYNC_CIRCUIT_OPENED,
                            peer_id=peer_id,
                            target_id=str(peer_id),
                            outcome=AuditOutcome.SUCCESS,
                            actor_id=actor,
                            reason="key_collision",
                            session=session,
                        )
                    collision_error = FederationError("key-collision", "Key collision detected for existing kid.")
                    status_detail = "collision-rejected"

                peer.last_key_refresh_at = now
                peer.updated_at = now
                if collision_error is None:
                    self._write_operational_audit(
                        action=AuditAction.PEER_KEY_APPROVE,
                        peer_id=peer_id,
                        target_type=AuditTargetType.PEER_KEY,
                        target_id=kid,
                        outcome=AuditOutcome.SUCCESS,
                        actor_id=actor,
                        reason=reason[:1024],
                        details={"result": status_detail, "fingerprint": actual_fingerprint},
                        session=session,
                    )
            if collision_error is not None:
                raise collision_error
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                approved = session.execute(
                    select(FederationPeerSigningKey)
                    .where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.kid == kid,
                    )
                ).scalar_one()
                return self._to_peer_key_inventory_item(peer=peer, key=approved)
        except FederationError as exc:
            if exc.code not in {"peer-not-found", "key-collision"}:
                with self.db.transaction() as session:
                    peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                    if peer is not None:
                        self._write_operational_audit(
                            action=AuditAction.PEER_KEY_APPROVE,
                            peer_id=peer_id,
                            target_type=AuditTargetType.PEER_KEY,
                            target_id=kid[:128],
                            outcome=AuditOutcome.REJECTED,
                            actor_id=actor,
                            reason=exc.code,
                            details={"errorCode": exc.code},
                            session=session,
                        )
            raise
        finally:
            try:
                self._release_lease(lease)
            except Exception:
                logger.exception("Failed to release approve lease for peer %s", peer_id)

    def retire_peer_key(
        self,
        *,
        peer_id: uuid.UUID,
        kid: str,
        reason: str,
        expected_status: str | None,
        actor: str,
    ) -> PeerKeyInventoryItem:
        lease = self._claim_lease(peer_id=peer_id, trigger_type="manual")
        if lease is None:
            raise FederationError("already-running", "Synchronization already running for this peer.")
        try:
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                key = session.execute(
                    select(FederationPeerSigningKey)
                    .where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.kid == kid,
                    )
                    .with_for_update()
                ).scalar_one_or_none()
                if key is None:
                    raise FederationError("peer-key-not-found", "Requested key kid was not found.")
                if expected_status is not None and key.key_status != expected_status:
                    raise FederationError("peer-key-status-stale", "Expected key status does not match current value.")
                if key.key_status == "revoked":
                    raise FederationError("peer-key-status-conflict", "Revoked key cannot be retired.")
                active_keys = session.execute(
                    select(FederationPeerSigningKey)
                    .where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.key_status == "active",
                    )
                    .with_for_update()
                ).scalars().all()
                if (
                    key.key_status == "active"
                    and peer.trust_status == "trusted"
                    and peer.sync_enabled
                    and len(active_keys) <= 1
                ):
                    raise FederationError("peer-key-last-active", "Cannot retire the last active key while synchronization remains enabled.")

                if key.key_status == "retired":
                    outcome = "idempotent-retired"
                else:
                    db_now = session.execute(select(func.now())).scalar_one()
                    key.key_status = "retired"
                    key.valid_until = db_now
                    key.updated_at = db_now
                    key.approved_by = actor[:128]
                    key.approved_at = db_now
                    outcome = "retired"
                self._write_operational_audit(
                    action=AuditAction.PEER_KEY_RETIRE,
                    peer_id=peer_id,
                    target_type=AuditTargetType.PEER_KEY,
                    target_id=kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor,
                    reason=reason[:1024],
                    details={"oldStatus": key.key_status if outcome == "idempotent-retired" else "active", "newStatus": "retired", "result": outcome},
                    session=session,
                )
                item = self._to_peer_key_inventory_item(peer=peer, key=key)
            return item
        except FederationError as exc:
            if exc.code != "peer-not-found":
                with self.db.transaction() as session:
                    peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                    if peer is not None:
                        self._write_operational_audit(
                            action=AuditAction.PEER_KEY_RETIRE,
                            peer_id=peer_id,
                            target_type=AuditTargetType.PEER_KEY,
                            target_id=kid[:128],
                            outcome=AuditOutcome.REJECTED,
                            actor_id=actor,
                            reason=exc.code,
                            details={"errorCode": exc.code},
                            session=session,
                        )
            raise
        finally:
            try:
                self._release_lease(lease)
            except Exception:
                logger.exception("Failed to release retire lease for peer %s", peer_id)

    def revoke_peer_key(
        self,
        *,
        peer_id: uuid.UUID,
        kid: str,
        reason: str,
        expected_status: str | None,
        actor: str,
    ) -> PeerKeyInventoryItem:
        lease = self._claim_lease(peer_id=peer_id, trigger_type="manual")
        if lease is None:
            raise FederationError("already-running", "Synchronization already running for this peer.")
        try:
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                key = session.execute(
                    select(FederationPeerSigningKey)
                    .where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.kid == kid,
                    )
                    .with_for_update()
                ).scalar_one_or_none()
                if key is None:
                    raise FederationError("peer-key-not-found", "Requested key kid was not found.")
                if expected_status is not None and key.key_status != expected_status:
                    raise FederationError("peer-key-status-stale", "Expected key status does not match current value.")
                active_keys = session.execute(
                    select(FederationPeerSigningKey)
                    .where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.key_status == "active",
                    )
                    .with_for_update()
                ).scalars().all()
                if (
                    key.key_status == "active"
                    and peer.trust_status == "trusted"
                    and peer.sync_enabled
                    and len(active_keys) <= 1
                ):
                    raise FederationError("peer-key-last-active", "Cannot revoke the last active key while synchronization remains enabled.")

                previous_status = key.key_status
                if key.key_status != "revoked":
                    db_now = session.execute(select(func.now())).scalar_one()
                    key.key_status = "revoked"
                    key.valid_until = db_now
                    key.updated_at = db_now
                    key.approved_by = actor[:128]
                    key.approved_at = db_now
                    if previous_status == "active":
                        previous_circuit_state = peer.circuit_state
                        self.circuit.mark_failure(
                            peer,
                            classification=self.circuit.classify_failure(
                                FederationError("revoked-signing-key", "Peer key was revoked by administrator."),
                                phase="jwks",
                            ),
                        )
                        if previous_circuit_state != CircuitState.OPEN.value and peer.circuit_state == CircuitState.OPEN.value:
                            self._write_operational_audit(
                                action=AuditAction.SYNC_CIRCUIT_OPENED,
                                peer_id=peer_id,
                                target_id=str(peer_id),
                                outcome=AuditOutcome.SUCCESS,
                                actor_id=actor,
                                reason="revoked_key_detected",
                                session=session,
                            )
                    outcome = "revoked"
                else:
                    outcome = "idempotent-revoked"
                self._write_operational_audit(
                    action=AuditAction.PEER_KEY_REVOKE,
                    peer_id=peer_id,
                    target_type=AuditTargetType.PEER_KEY,
                    target_id=kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor,
                    reason=reason[:1024],
                    details={"oldStatus": previous_status, "newStatus": "revoked", "result": outcome},
                    session=session,
                )
                item = self._to_peer_key_inventory_item(peer=peer, key=key)
            return item
        except FederationError as exc:
            if exc.code != "peer-not-found":
                with self.db.transaction() as session:
                    peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                    if peer is not None:
                        self._write_operational_audit(
                            action=AuditAction.PEER_KEY_REVOKE,
                            peer_id=peer_id,
                            target_type=AuditTargetType.PEER_KEY,
                            target_id=kid[:128],
                            outcome=AuditOutcome.REJECTED,
                            actor_id=actor,
                            reason=exc.code,
                            details={"errorCode": exc.code},
                            session=session,
                        )
            raise
        finally:
            try:
                self._release_lease(lease)
            except Exception:
                logger.exception("Failed to release revoke lease for peer %s", peer_id)

    def create_peer(self, *, payload: PeerCreateRequest, actor: str) -> PeerResponse:
        now = datetime.now(timezone.utc)
        allowed_hostnames = tuple(payload.allowedHostnames)
        allowed_cidrs = tuple(payload.allowedCidrs)
        discovery, jwks = self._fetch_and_validate_peer_snapshot(
            base_url=payload.baseUrl,
            allow_private_network=payload.allowPrivateNetwork,
            expected_node_id=payload.peerNodeId,
            allowed_hostnames=allowed_hostnames,
            allowed_cidrs=allowed_cidrs,
        )
        trusted_key = self._validate_enrollment_key(payload=payload, jwks=jwks)

        with self.db.transaction() as session:
            existing = (
                session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.peer_node_id == payload.peerNodeId))
                .scalars()
                .one_or_none()
            )
            if existing is not None:
                raise FederationError("peer-exists", "A trusted peer with this node ID already exists.")
            peer = FederationTrustedPeer(
                id=uuid.uuid4(),
                peer_node_id=payload.peerNodeId,
                base_url=payload.baseUrl.rstrip("/"),
                jwks_url=discovery.jwksUrl,
                peer_name=payload.peerName,
                operator_name=payload.operatorName,
                trust_status="trusted",
                sync_enabled=True,
                allow_private_network=payload.allowPrivateNetwork,
                allowed_hostnames=",".join(payload.allowedHostnames) if payload.allowedHostnames else None,
                allowed_cidrs=",".join(payload.allowedCidrs) if payload.allowedCidrs else None,
                enrollment_mode="tofu-unsafe" if (payload.demoTofuConfirm and self.settings.demo_tofu_unsafe_enabled) else "strict",
                expected_key_fingerprint=trusted_key["fingerprint"],
                expected_key_kid=trusted_key["kid"],
                created_at=now,
                updated_at=now,
            )
            session.add(peer)
            session.flush()
            self._upsert_peer_key(
                session=session,
                peer=peer,
                kid=trusted_key["kid"],
                x=trusted_key["x"],
                key_status="active",
                actor=actor,
            )
            session.add(
                FederationPeerCursor(
                    id=uuid.uuid4(),
                    peer_id=peer.id,
                    cursor=None,
                    last_remote_position=0,
                    synced_at=None,
                    updated_at=now,
                )
            )
            self._audit(session, peer.id, "peer.created", actor, {"baseUrl": payload.baseUrl, "peerNodeId": payload.peerNodeId})
        return self.get_peer(peer.id)

    def patch_peer(self, *, peer_id: uuid.UUID, payload: PeerPatchRequest, actor: str) -> PeerResponse:
        with self.db.transaction() as session:
            peer = session.execute(
                select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
            ).scalar_one_or_none()
            if peer is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            current_base_url = peer.base_url
            current_node_id = peer.peer_node_id
            current_allow_private_network = peer.allow_private_network
            current_allow_hostnames, current_allow_cidrs = self._combined_allowlists(
                peer_allowed_hostnames=peer.allowed_hostnames,
                peer_allowed_cidrs=peer.allowed_cidrs,
            )

        needs_reenrollment = (
            payload.baseUrl is not None
            or payload.verificationKey is not None
            or payload.trustStatus == "trusted"
            or payload.syncEnabled is True
        )
        if needs_reenrollment:
            target_base_url = payload.baseUrl or current_base_url
            allowed_hostnames = tuple(payload.allowedHostnames) if payload.allowedHostnames is not None else current_allow_hostnames
            allowed_cidrs = tuple(payload.allowedCidrs) if payload.allowedCidrs is not None else current_allow_cidrs
            allow_private_network = payload.allowPrivateNetwork if payload.allowPrivateNetwork is not None else current_allow_private_network
            if payload.verificationKey is None:
                raise FederationError("peer-key-required", "Updating base URL or peer identity requires an explicitly approved verification key.")
            discovery, jwks = self._fetch_and_validate_peer_snapshot(
                base_url=target_base_url,
                allow_private_network=allow_private_network,
                expected_node_id=current_node_id,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
            match = next((k for k in jwks.keys if k.kid == payload.verificationKey.kid), None)
            if match is None:
                raise FederationError("peer-key-not-found", "Requested key kid was not found in peer JWKS.")
            fingerprint = ed25519_key_fingerprint_hex(match.x)
            if fingerprint != payload.verificationKey.fingerprint:
                raise FederationError("peer-key-mismatch", "Provided key fingerprint does not match peer JWKS key.")
        else:
            discovery = None
            jwks = None
            target_base_url = current_base_url
            allowed_hostnames = tuple(payload.allowedHostnames) if payload.allowedHostnames is not None else current_allow_hostnames
            allowed_cidrs = tuple(payload.allowedCidrs) if payload.allowedCidrs is not None else current_allow_cidrs
            fingerprint = None

        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            if payload.baseUrl is not None:
                peer.base_url = target_base_url.rstrip("/")
                peer.jwks_url = discovery.jwksUrl if discovery is not None else peer.jwks_url
            if payload.peerName is not None:
                peer.peer_name = payload.peerName
            if payload.operatorName is not None:
                peer.operator_name = payload.operatorName
            if payload.syncEnabled is not None:
                peer.sync_enabled = payload.syncEnabled
            if payload.allowPrivateNetwork is not None:
                peer.allow_private_network = payload.allowPrivateNetwork
            if payload.allowedHostnames is not None:
                peer.allowed_hostnames = ",".join(payload.allowedHostnames) if payload.allowedHostnames else None
            if payload.allowedCidrs is not None:
                peer.allowed_cidrs = ",".join(payload.allowedCidrs) if payload.allowedCidrs else None
            if payload.trustStatus is not None:
                peer.trust_status = payload.trustStatus
                if payload.trustStatus == "archived":
                    peer.archived_at = datetime.now(timezone.utc)
                    peer.sync_enabled = False
            if payload.verificationKey is not None and jwks is not None:
                match = next((k for k in jwks.keys if k.kid == payload.verificationKey.kid), None)
                if match is None:
                    raise FederationError("peer-key-not-found", "Requested key kid was not found in peer JWKS.")
                existing_key = session.execute(
                    select(FederationPeerSigningKey).where(
                        FederationPeerSigningKey.peer_id == peer.id,
                        FederationPeerSigningKey.kid == match.kid,
                    )
                ).scalar_one_or_none()
                if existing_key is None:
                    raise FederationError(
                        "peer-key-approval-required",
                        "Peer key is not yet approved. Run inspect and explicit approval before updating peer settings.",
                    )
                if existing_key.key_fingerprint != (fingerprint or ""):
                    raise FederationError(
                        "key-collision",
                        "Stored peer key fingerprint differs for the same kid; approval workflow is required.",
                    )
                if existing_key.key_status != "active":
                    raise FederationError("peer-key-status-conflict", "Only active approved keys may authorize peer updates.")
                existing_key.last_seen_at = datetime.now(timezone.utc)
                existing_key.updated_at = datetime.now(timezone.utc)
            peer.updated_at = datetime.now(timezone.utc)
            self._audit(session, peer.id, "peer.updated", actor, payload.model_dump(exclude_none=True))
        return self.get_peer(peer_id)

    def archive_peer(self, *, peer_id: uuid.UUID, actor: str) -> PeerResponse:
        return self.patch_peer(
            peer_id=peer_id,
            payload=PeerPatchRequest(trustStatus="archived", syncEnabled=False),
            actor=actor,
        )

    def _claim_lease(self, *, peer_id: uuid.UUID, trigger_type: str) -> ClaimedLease | None:
        try:
            with self.db.transaction() as session:
                return self.lease_repo.claim_sync(
                    session,
                    peer_id=peer_id,
                    owner_instance_id=self.owner_instance_id,
                    trigger_type=trigger_type,
                    duration_seconds=self.settings.sync_lease_duration_seconds,
                )
        except IntegrityError as exc:
            raise FederationError("peer-not-found", "Trusted peer was not found.") from exc

    def _release_lease(self, lease: ClaimedLease) -> None:
        with self.db.transaction() as session:
            self.lease_repo.release_sync(
                session,
                peer_id=lease.peer_id,
                owner_instance_id=lease.owner_instance_id,
                fencing_token=lease.fencing_token,
            )

    def _write_operational_audit(
        self,
        *,
        action: AuditAction,
        peer_id: uuid.UUID,
        target_type: AuditTargetType = AuditTargetType.PEER,
        target_id: str,
        outcome: AuditOutcome,
        actor_id: str | None,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        def _write_row(target_session: Session) -> None:
            write_audit_row_sync(
                target_session,
                actor_type=AuditActorType.HUMAN_OPERATOR if actor_id else AuditActorType.WORKER,
                action=action,
                target_type=target_type,
                target_id=target_id,
                peer_id=peer_id,
                outcome=outcome,
                actor_id=actor_id,
                reason=reason,
                details=details,
            )

        if session is not None:
            _write_row(session)
            return
        with self.db.transaction() as local_session:
            _write_row(local_session)

    def _record_health_snapshot(
        self,
        *,
        peer_id: uuid.UUID,
        peer_node_id: str,
        discovery_reachable: bool | None,
        jwks_reachable: bool | None,
        feed_reachable: bool | None,
        last_event_position: int | None,
        round_trip_ms: int | None,
        health_status: str,
        compatibility_status: str,
        error_code: str | None,
        error_detail: str | None,
        session: Session | None = None,
    ) -> None:
        safe_detail = sanitize_free_text(error_detail, max_len=1024) if error_detail else None

        def _add_row(target_session: Session) -> None:
            target_session.add(
                FederationPeerHealthSnapshot(
                    id=uuid.uuid4(),
                    peer_id=peer_id,
                    peer_node_id=peer_node_id[:256],
                    sampled_at=datetime.now(timezone.utc),
                    discovery_reachable=discovery_reachable,
                    jwks_reachable=jwks_reachable,
                    feed_reachable=feed_reachable,
                    last_event_position=last_event_position,
                    round_trip_ms=round_trip_ms if round_trip_ms is None else max(0, round_trip_ms),
                    health_status=health_status,
                    compatibility_status=compatibility_status,
                    error_code=error_code[:64] if error_code else None,
                    error_detail=safe_detail,
                    created_at=datetime.now(timezone.utc),
                )
            )
        if session is not None:
            _add_row(session)
            return
        with self.db.transaction() as local_session:
            _add_row(local_session)

    def suspend_peer(self, *, peer_id: uuid.UUID, reason: str, suspended_until: datetime | None, actor: str) -> PeerResponse:
        now = datetime.now(timezone.utc)
        if suspended_until is not None:
            if suspended_until.tzinfo is None or suspended_until.utcoffset() is None:
                raise FederationError("invalid-suspension", "suspendedUntil must include timezone information.")
            if suspended_until <= now:
                raise FederationError("invalid-suspension", "suspendedUntil must be in the future.")
        with self.db.transaction() as session:
            peer = session.execute(
                select(FederationTrustedPeer)
                .where(FederationTrustedPeer.id == peer_id)
                .with_for_update()
            ).scalar_one_or_none()
            if peer is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            peer.suspension_reason = reason[:1024]
            peer.suspended_until = suspended_until
            peer.updated_at = now
            self._audit(session, peer.id, "peer.suspended", actor, {"reason": reason[:256], "suspendedUntil": suspended_until.isoformat() if suspended_until else None})
            self._write_operational_audit(
                action=AuditAction.PEER_SUSPEND,
                peer_id=peer_id,
                target_id=str(peer_id),
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor,
                reason=reason[:1024],
                details={"suspendedUntil": suspended_until.isoformat() if suspended_until else None},
                session=session,
            )
        return self.get_peer(peer_id)

    def resume_peer(self, *, peer_id: uuid.UUID, reason: str | None, actor: str) -> PeerResponse:
        with self.db.transaction() as session:
            peer = session.execute(
                select(FederationTrustedPeer)
                .where(FederationTrustedPeer.id == peer_id)
                .with_for_update()
            ).scalar_one_or_none()
            if peer is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
            peer.suspension_reason = None
            peer.suspended_until = None
            peer.updated_at = datetime.now(timezone.utc)
            self._audit(session, peer.id, "peer.resumed", actor, {"reason": (reason or "")[:256]})
            self._write_operational_audit(
                action=AuditAction.PEER_RESUME,
                peer_id=peer_id,
                target_id=str(peer_id),
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor,
                reason=(reason or "")[:1024] if reason else None,
                session=session,
            )
        return self.get_peer(peer_id)

    def reset_peer_circuit(self, *, peer_id: uuid.UUID, reason: str, expected_state: str | None, actor: str) -> PeerResponse:
        lease = self._claim_lease(peer_id=peer_id, trigger_type="manual")
        if lease is None:
            raise FederationError("circuit-reset-race", "Peer synchronization lease is currently active.")
        try:
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                if expected_state is not None and expected_state != peer.circuit_state:
                    raise FederationError("circuit-state-stale", "Expected circuit state does not match current state.")
                self.circuit.reset(peer)
                peer.updated_at = datetime.now(timezone.utc)
                self._audit(session, peer.id, "peer.circuit-reset", actor, {"reason": reason[:256], "expectedState": expected_state})
                self._write_operational_audit(
                    action=AuditAction.PEER_CIRCUIT_RESET,
                    peer_id=peer_id,
                    target_id=str(peer_id),
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor,
                    reason=reason[:1024],
                    details={"expectedState": expected_state},
                    session=session,
                )
            return self.get_peer(peer_id)
        finally:
            try:
                self._release_lease(lease)
            except Exception:
                logger.exception("Failed to release circuit-reset lease for peer %s", peer_id)

    def probe_peer(self, *, peer_id: uuid.UUID, actor: str) -> dict[str, Any]:
        lease = self._claim_lease(peer_id=peer_id, trigger_type="probe")
        if lease is None:
            raise FederationError("already-running", "Synchronization already running for this peer.")
        started = datetime.now(timezone.utc)
        peer_node_id = None
        phase = "discovery"
        attempted_remote = False
        discovery_reachable = False
        jwks_reachable = False
        expected_node_id = ""
        try:
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                peer_node_id = peer.peer_node_id
                allowed_hostnames, allowed_cidrs = self._combined_allowlists(
                    peer_allowed_hostnames=peer.allowed_hostnames,
                    peer_allowed_cidrs=peer.allowed_cidrs,
                )
                if peer.archived_at is not None:
                    raise FederationError("peer-archived", "Peer is archived.")
                if peer.trust_status != "trusted" or not peer.sync_enabled:
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
                now = datetime.now(timezone.utc)
                if peer.suspension_reason and (peer.suspended_until is None or peer.suspended_until > now):
                    raise FederationError("peer-suspended", "Peer is administratively suspended.")
                gate = self.circuit.evaluate_gate(peer)
                if gate.transitioned:
                    self._write_operational_audit(
                        action=AuditAction.SYNC_CIRCUIT_HALF_OPENED,
                        peer_id=peer_id,
                        target_id=str(peer_id),
                        outcome=AuditOutcome.SUCCESS,
                        actor_id=actor,
                        details={"state": gate.state.value},
                        session=session,
                    )
                if not gate.allowed:
                    raise FederationError("circuit-open-admin-reset" if gate.reason == "circuit-open-admin-reset" else "circuit-open", "Peer circuit is open.")
                base_url = peer.base_url
                allow_private_network = peer.allow_private_network
                expected_node_id = peer.peer_node_id
            attempted_remote = True
            discovery = self._fetch_discovery(
                base_url,
                allow_private_network=allow_private_network,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
            discovery_reachable = True
            if discovery.nodeId != expected_node_id:
                raise FederationError("peer-node-mismatch", "Discovery nodeId does not match requested peerNodeId.")
            if discovery.publicBaseUrl.rstrip("/") != base_url.rstrip("/"):
                raise FederationError("peer-base-url-mismatch", "Discovery publicBaseUrl does not match expected base URL.")
            phase = "jwks"
            jwks = self._fetch_jwks(
                discovery.jwksUrl,
                allow_private_network=allow_private_network,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
            jwks_reachable = True
            elapsed_ms = max(0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000))
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one()
                if peer.archived_at is not None:
                    raise FederationError("peer-archived", "Peer is archived.")
                if peer.trust_status != "trusted" or not peer.sync_enabled:
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
                pinned = session.execute(
                    select(FederationPeerSigningKey).where(
                        FederationPeerSigningKey.peer_id == peer_id,
                        FederationPeerSigningKey.key_status.in_(["active", "retired"]),
                    )
                ).scalars().all()
                advertised = {item.kid for item in jwks.keys}
                missing = sorted({k.kid for k in pinned} - advertised)
                if missing:
                    raise FederationError("peer-key-missing", "Peer JWKS no longer advertises a pinned signing key.")
                circuit_closed = self.circuit.mark_success(peer)
                self._record_health_snapshot(
                    peer_id=peer_id,
                    peer_node_id=peer_node_id,
                    discovery_reachable=discovery_reachable,
                    jwks_reachable=jwks_reachable,
                    feed_reachable=None,
                    last_event_position=None,
                    round_trip_ms=elapsed_ms,
                    health_status="healthy",
                    compatibility_status="unchecked",
                    error_code=None,
                    error_detail=None,
                    session=session,
                )
                self._write_operational_audit(
                    action=AuditAction.PEER_PROBE,
                    peer_id=peer_id,
                    target_id=str(peer_id),
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor,
                    details={"roundTripMs": elapsed_ms, "reachableDiscovery": discovery_reachable, "reachableJwks": jwks_reachable},
                    session=session,
                )
                if circuit_closed:
                    self._write_operational_audit(
                        action=AuditAction.SYNC_CIRCUIT_CLOSED,
                        peer_id=peer_id,
                        target_id=str(peer_id),
                        outcome=AuditOutcome.SUCCESS,
                        actor_id=actor,
                        session=session,
                    )
                state = peer.circuit_state
            return {
                "peerId": peer_id,
                "peerNodeId": expected_node_id,
                "reachableDiscovery": True,
                "reachableJwks": True,
                "roundTripMs": elapsed_ms,
                "healthStatus": "healthy",
                "errorCode": None,
                "circuitState": state,
                "sampledAt": datetime.now(timezone.utc),
            }
        except FederationError as exc:
            classification = self.circuit.classify_failure(exc, phase=phase)
            elapsed_ms = max(0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000))
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                opened_circuit = False
                if peer is not None and classification.kind in {"transient", "permanent"}:
                    previous_state = peer.circuit_state
                    self.circuit.mark_failure(peer, classification=classification)
                    opened_circuit = previous_state != CircuitState.OPEN.value and peer.circuit_state == CircuitState.OPEN.value
                    state = peer.circuit_state
                    node_id = peer.peer_node_id
                elif peer is not None:
                    state = peer.circuit_state
                    node_id = peer.peer_node_id
                else:
                    state = "closed"
                    node_id = peer_node_id or ""
                if attempted_remote and node_id:
                    self._record_health_snapshot(
                        peer_id=peer_id,
                        peer_node_id=node_id,
                        discovery_reachable=discovery_reachable,
                        jwks_reachable=jwks_reachable,
                        feed_reachable=None,
                        last_event_position=None,
                        round_trip_ms=elapsed_ms,
                        health_status="unreachable" if exc.code in {"remote-unreachable", "remote-server-error", "remote-tls-error"} else "degraded",
                        compatibility_status="unknown",
                        error_code=exc.code,
                        error_detail=_safe_health_error_detail(exc),
                        session=session,
                    )
                self._write_operational_audit(
                    action=AuditAction.PEER_PROBE,
                    peer_id=peer_id,
                    target_id=str(peer_id),
                    outcome=AuditOutcome.BLOCKED if exc.code in {"circuit-open", "circuit-open-admin-reset"} else AuditOutcome.FAILED,
                    actor_id=actor,
                    reason=exc.code,
                    details=AuditDetailBuilder().add("errorCode", exc.code).add("roundTripMs", elapsed_ms).build(),
                    session=session,
                )
                if opened_circuit:
                    self._write_operational_audit(
                        action=AuditAction.SYNC_CIRCUIT_OPENED,
                        peer_id=peer_id,
                        target_id=str(peer_id),
                        outcome=AuditOutcome.SUCCESS,
                        actor_id=actor,
                        reason=classification.reason.value if classification.reason else None,
                        session=session,
                    )
            raise
        finally:
            if lease is not None:
                try:
                    self._release_lease(lease)
                except Exception:
                    logger.exception("Failed to release probe lease for peer %s", peer_id)

    def _fetch_discovery(
        self,
        base_url: str,
        *,
        allow_private_network: bool,
        allowed_hostnames: tuple[str, ...] = (),
        allowed_cidrs: tuple[str, ...] = (),
    ) -> RemoteDiscoveryResponse:
        try:
            payload = self.remote_client.get_json(
                f"{base_url.rstrip('/')}/.well-known/lfs",
                limits=_HttpLimits(self.settings.sync_max_discovery_bytes, "application/json"),
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
        except FederationError:
            raise
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote discovery document failed validation.") from exc
        except Exception as exc:
            raise FederationError("remote-unreachable", "Failed to retrieve peer discovery document.") from exc
        try:
            return RemoteDiscoveryResponse.model_validate(payload)
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote discovery document failed validation.") from exc

    def _fetch_jwks(
        self,
        jwks_url: str,
        *,
        allow_private_network: bool,
        allowed_hostnames: tuple[str, ...] = (),
        allowed_cidrs: tuple[str, ...] = (),
    ) -> RemoteJwksResponse:
        try:
            payload = self.remote_client.get_json(
                jwks_url,
                limits=_HttpLimits(self.settings.sync_max_jwks_bytes, "application/jwk-set+json"),
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
        except FederationError:
            raise
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote JWKS document failed validation.") from exc
        except Exception as exc:
            raise FederationError("remote-unreachable", "Failed to retrieve peer JWKS document.") from exc
        try:
            model = RemoteJwksResponse.model_validate(payload)
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote JWKS document failed validation.") from exc
        if len(model.keys) > self.settings.sync_max_jwks_keys:
            raise FederationError("peer-jwks-too-many-keys", "Peer JWKS key count exceeds configured maximum.")
        return model

    def _validate_enrollment_key(self, *, payload: PeerCreateRequest, jwks: RemoteJwksResponse) -> dict[str, str]:
        if payload.verificationKey is None:
            if not (self.settings.demo_tofu_unsafe_enabled and payload.demoTofuConfirm):
                raise FederationError(
                    "peer-key-required",
                    "Enrollment requires explicit verification key expectation (kid + fingerprint).",
                )
            if not jwks.keys:
                raise FederationError("peer-key-not-found", "Peer JWKS does not include any keys for demo TOFU.")
            chosen = jwks.keys[0]
            return {
                "kid": chosen.kid,
                "x": chosen.x,
                "fingerprint": ed25519_key_fingerprint_hex(chosen.x),
            }

        match = next((item for item in jwks.keys if item.kid == payload.verificationKey.kid), None)
        if match is None:
            raise FederationError("peer-key-not-found", "Expected key kid was not found in peer JWKS.")
        actual = ed25519_key_fingerprint_hex(match.x)
        if actual != payload.verificationKey.fingerprint:
            raise FederationError("peer-key-mismatch", "Expected key fingerprint does not match peer JWKS key.")
        return {"kid": match.kid, "x": match.x, "fingerprint": actual}

    @staticmethod
    def _audit(session: Session, peer_id: uuid.UUID, action: str, actor: str, details: dict[str, Any]) -> None:
        session.add(
            FederationPeerAuditLog(
                id=uuid.uuid4(),
                peer_id=peer_id,
                action=action,
                actor=actor,
                details=details,
                created_at=datetime.now(timezone.utc),
            )
        )

    @staticmethod
    def _to_peer_response(peer: FederationTrustedPeer, latest_health: dict | None = None) -> PeerResponse:
        return PeerResponse(
            id=peer.id,
            peerNodeId=peer.peer_node_id,
            baseUrl=peer.base_url,
            peerName=peer.peer_name,
            operatorName=peer.operator_name,
            trustStatus=peer.trust_status,
            syncEnabled=peer.sync_enabled,
            lastSyncAttemptAt=peer.last_sync_attempt_at,
            lastSyncSuccessAt=peer.last_sync_success_at,
            lastSyncStatus=peer.last_sync_status,
            lastSyncErrorCode=peer.last_sync_error_code,
            expectedKeyKid=peer.expected_key_kid,
            expectedKeyFingerprint=peer.expected_key_fingerprint,
            archivedAt=peer.archived_at,
            # Phase 5 circuit breaker
            circuitState=peer.circuit_state,
            circuitRequiresAdminReset=peer.circuit_requires_admin_reset,
            circuitFailureCount=peer.circuit_failure_count,
            circuitOpenedAt=peer.circuit_opened_at,
            circuitNextAttemptAt=peer.circuit_next_attempt_at,
            circuitLastFailureReason=peer.circuit_last_failure_reason,
            # Phase 5 administrative suspension
            suspendedUntil=peer.suspended_until,
            suspensionReason=peer.suspension_reason,
            # Phase 5 key management
            lastKeyRefreshAt=peer.last_key_refresh_at,
            # Phase 5 health
            latestHealthStatus=latest_health.get("health_status") if latest_health else None,
            latestCompatibilityStatus=latest_health.get("compatibility_status") if latest_health else None,
        )

    def _upsert_peer_key(
        self,
        *,
        session: Session,
        peer: FederationTrustedPeer,
        kid: str,
        x: str,
        key_status: str,
        actor: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        existing = (
            session.execute(
                select(FederationPeerSigningKey).where(
                    FederationPeerSigningKey.peer_id == peer.id,
                    FederationPeerSigningKey.kid == kid,
                )
            )
            .scalars()
            .one_or_none()
        )
        fingerprint = ed25519_key_fingerprint_hex(x)
        if existing is None:
            session.add(
                FederationPeerSigningKey(
                    id=uuid.uuid4(),
                    peer_id=peer.id,
                    kid=kid,
                    alg="EdDSA",
                    kty="OKP",
                    crv="Ed25519",
                    x=x,
                    key_fingerprint=fingerprint,
                    key_status=key_status,
                    first_seen_at=now,
                    last_seen_at=now,
                    approved_by=actor,
                    approved_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            return
        existing.x = x
        existing.key_fingerprint = fingerprint
        existing.key_status = key_status
        existing.last_seen_at = now
        existing.approved_by = actor
        existing.approved_at = now
        existing.updated_at = now

    def _refresh_peer_verification_state(
        self,
        *,
        peer_id: uuid.UUID,
        allowlists: tuple[tuple[str, ...], tuple[str, ...]],
        trigger_type: str,
    ) -> None:
        allowed_hostnames, allowed_cidrs = allowlists
        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is None or peer.trust_status != "trusted" or not peer.sync_enabled:
                return
            current_base_url = peer.base_url
            current_node_id = peer.peer_node_id
            allow_private_network = peer.allow_private_network
        try:
            discovery, jwks = self.peer_service._fetch_and_validate_peer_snapshot(
                base_url=current_base_url,
                allow_private_network=allow_private_network,
                expected_node_id=current_node_id,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
        except FederationError as exc:
            if exc.code == "remote-unreachable":
                return
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                if peer is None:
                    return
                peer.trust_status = "review_required"
                peer.sync_enabled = False
                peer.last_sync_status = "failed"
                peer.last_sync_error_code = exc.code
                peer.last_sync_error_detail = exc.detail[:256]
                peer.updated_at = datetime.now(timezone.utc)
                session.add(
                    FederationPeerAuditLog(
                        id=uuid.uuid4(),
                        peer_id=peer_id,
                        action="peer.review-required",
                        actor=trigger_type,
                        details={"code": exc.code, "detail": exc.detail[:256]},
                        created_at=datetime.now(timezone.utc),
                    )
                )
            raise

        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is None:
                return
            pinned = session.execute(
                select(FederationPeerSigningKey).where(
                    FederationPeerSigningKey.peer_id == peer_id,
                    FederationPeerSigningKey.key_status.in_(["active", "retired"]),
                )
            ).scalars().all()
            pinned_kids = {item.kid for item in pinned}
            advertised_kids = {item.kid for item in jwks.keys}
            missing = sorted(pinned_kids - advertised_kids)
            if missing:
                peer.trust_status = "review_required"
                peer.sync_enabled = False
                peer.last_sync_status = "failed"
                peer.last_sync_error_code = "peer-key-missing"
                peer.last_sync_error_detail = f"Missing pinned key(s): {','.join(missing)}"
                peer.updated_at = datetime.now(timezone.utc)
                session.add(
                    FederationPeerAuditLog(
                        id=uuid.uuid4(),
                        peer_id=peer_id,
                        action="peer.review-required",
                        actor=trigger_type,
                        details={"missingKids": missing},
                        created_at=datetime.now(timezone.utc),
                    )
                )
                missing_error = FederationError("peer-key-missing", "Peer JWKS no longer advertises a pinned signing key.")
            else:
                missing_error = None
            now = datetime.now(timezone.utc)
            for key in pinned:
                if key.kid in advertised_kids:
                    key.last_seen_at = now
                    key.updated_at = now
            peer.updated_at = now
        if missing_error is not None:
            raise missing_error

    def _finalize_sync_attempt(
        self,
        *,
        peer_id: uuid.UUID,
        attempt_id: uuid.UUID,
        status: str,
        error: FederationError,
        stats: _SyncStats,
    ) -> None:
        detail = error.detail[:256]
        with self.db.transaction() as session:
            attempt = session.execute(select(FederationSyncAttempt).where(FederationSyncAttempt.id == attempt_id)).scalar_one_or_none()
            if attempt is not None:
                attempt.status = status
                attempt.error_code = error.code
                attempt.error_detail = detail
                attempt.pages_processed = stats.pages_processed
                attempt.events_processed = stats.events_processed
                attempt.cursor_after = stats.cursor_after
                attempt.completed_at = datetime.now(timezone.utc)
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is not None:
                peer.last_sync_status = status
                peer.last_sync_error_code = error.code
                peer.last_sync_error_detail = detail
                peer.updated_at = datetime.now(timezone.utc)


@dataclass
class _SyncStats:
    pages_processed: int = 0
    events_processed: int = 0
    imported_records: int = 0
    cursor_before: str | None = None
    cursor_after: str | None = None


class FederationInboundSyncService:
    def __init__(
        self,
        db: Database,
        settings: FederationSettings,
        remote_client: FederationRemoteClient | None = None,
        *,
        owner_instance_id: uuid.UUID | None = None,
        now_provider: Callable[[], datetime] | None = None,
        jitter_provider: Callable[[], float] | None = None,
    ):
        self.db = db
        self.settings = settings
        self.remote_client = remote_client or FederationRemoteClient(settings)
        self.peer_service = FederationPeerService(db, settings, remote_client=self.remote_client)
        self.rdf_outbox = RdfOutboxService(db, settings)
        self.owner_instance_id = owner_instance_id or uuid.uuid4()
        self.lease_repo = SyncLeaseRepository()
        self.circuit = PeerCircuitService(
            settings,
            now_provider=now_provider or (lambda: datetime.now(timezone.utc)),
            jitter_provider=jitter_provider or (lambda: random.uniform(0.75, 1.25)),
        )

    def _refresh_peer_verification_state(
        self,
        *,
        peer_id: uuid.UUID,
        allowlists: tuple[tuple[str, ...], tuple[str, ...]],
        trigger_type: str,
    ) -> None:
        allowed_hostnames, allowed_cidrs = allowlists
        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is None or peer.trust_status != "trusted" or not peer.sync_enabled:
                return
            current_base_url = peer.base_url
            current_node_id = peer.peer_node_id
            allow_private_network = peer.allow_private_network
        try:
            discovery, jwks = self.peer_service._fetch_and_validate_peer_snapshot(
                base_url=current_base_url,
                allow_private_network=allow_private_network,
                expected_node_id=current_node_id,
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
        except FederationError as exc:
            if exc.code == "remote-unreachable":
                return
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                if peer is None:
                    return
                peer.trust_status = "review_required"
                peer.sync_enabled = False
                peer.last_sync_status = "failed"
                peer.last_sync_error_code = exc.code
                peer.last_sync_error_detail = exc.detail[:256]
                peer.updated_at = datetime.now(timezone.utc)
                session.add(
                    FederationPeerAuditLog(
                        id=uuid.uuid4(),
                        peer_id=peer_id,
                        action="peer.review-required",
                        actor=trigger_type,
                        details={"code": exc.code, "detail": exc.detail[:256]},
                        created_at=datetime.now(timezone.utc),
                    )
                )
            raise

        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is None:
                return
            pinned = session.execute(
                select(FederationPeerSigningKey).where(
                    FederationPeerSigningKey.peer_id == peer_id,
                    FederationPeerSigningKey.key_status.in_(["active", "retired"]),
                )
            ).scalars().all()
            pinned_kids = {item.kid for item in pinned}
            advertised_kids = {item.kid for item in jwks.keys}
            missing = sorted(pinned_kids - advertised_kids)
            if missing:
                peer.trust_status = "review_required"
                peer.sync_enabled = False
                peer.last_sync_status = "failed"
                peer.last_sync_error_code = "peer-key-missing"
                peer.last_sync_error_detail = f"Missing pinned key(s): {','.join(missing)}"
                peer.updated_at = datetime.now(timezone.utc)
                session.add(
                    FederationPeerAuditLog(
                        id=uuid.uuid4(),
                        peer_id=peer_id,
                        action="peer.review-required",
                        actor=trigger_type,
                        details={"missingKids": missing},
                        created_at=datetime.now(timezone.utc),
                    )
                )
                missing_error = FederationError("peer-key-missing", "Peer JWKS no longer advertises a pinned signing key.")
            else:
                missing_error = None
            now = datetime.now(timezone.utc)
            for key in pinned:
                if key.kid in advertised_kids:
                    key.last_seen_at = now
                    key.updated_at = now
            peer.updated_at = now
        if missing_error is not None:
            raise missing_error

    def _finalize_sync_attempt(
        self,
        *,
        peer_id: uuid.UUID,
        attempt_id: uuid.UUID,
        status: str,
        error: FederationError,
        stats: _SyncStats,
    ) -> None:
        detail = error.detail[:256]
        with self.db.transaction() as session:
            attempt = session.execute(select(FederationSyncAttempt).where(FederationSyncAttempt.id == attempt_id)).scalar_one_or_none()
            if attempt is not None:
                attempt.status = status
                attempt.error_code = error.code
                attempt.error_detail = detail
                attempt.pages_processed = stats.pages_processed
                attempt.events_processed = stats.events_processed
                attempt.cursor_after = stats.cursor_after
                attempt.completed_at = datetime.now(timezone.utc)
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if peer is not None:
                peer.last_sync_status = status
                peer.last_sync_error_code = error.code
                peer.last_sync_error_detail = detail
                peer.updated_at = datetime.now(timezone.utc)

    def _claim_lease(self, *, peer_id: uuid.UUID, trigger_type: str) -> ClaimedLease | None:
        try:
            with self.db.transaction() as session:
                return self.lease_repo.claim_sync(
                    session,
                    peer_id=peer_id,
                    owner_instance_id=self.owner_instance_id,
                    trigger_type=trigger_type,
                    duration_seconds=self.settings.sync_lease_duration_seconds,
                )
        except IntegrityError as exc:
            raise FederationError("peer-not-found", "Trusted peer was not found.") from exc

    def _release_lease(self, lease: ClaimedLease) -> None:
        with self.db.transaction() as session:
            self.lease_repo.release_sync(
                session,
                peer_id=lease.peer_id,
                owner_instance_id=lease.owner_instance_id,
                fencing_token=lease.fencing_token,
            )

    def _write_operational_audit(
        self,
        *,
        action: AuditAction,
        peer_id: uuid.UUID,
        target_type: AuditTargetType = AuditTargetType.PEER,
        target_id: str,
        outcome: AuditOutcome,
        actor_id: str | None,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
        session: Session | None = None,
    ) -> None:
        def _write_row(target_session: Session) -> None:
            write_audit_row_sync(
                target_session,
                actor_type=AuditActorType.HUMAN_OPERATOR if actor_id else AuditActorType.WORKER,
                action=action,
                target_type=target_type,
                target_id=target_id,
                peer_id=peer_id,
                outcome=outcome,
                actor_id=actor_id,
                reason=reason,
                details=details,
            )

        if session is not None:
            _write_row(session)
            return
        with self.db.transaction() as local_session:
            _write_row(local_session)

    def _record_health_snapshot(
        self,
        *,
        peer_id: uuid.UUID,
        peer_node_id: str,
        discovery_reachable: bool | None,
        jwks_reachable: bool | None,
        feed_reachable: bool | None,
        last_event_position: int | None,
        round_trip_ms: int | None,
        health_status: str,
        compatibility_status: str,
        error_code: str | None,
        error_detail: str | None,
        session: Session | None = None,
    ) -> None:
        safe_detail = sanitize_free_text(error_detail, max_len=1024) if error_detail else None

        def _add_row(target_session: Session) -> None:
            target_session.add(
                FederationPeerHealthSnapshot(
                    id=uuid.uuid4(),
                    peer_id=peer_id,
                    peer_node_id=peer_node_id[:256],
                    sampled_at=datetime.now(timezone.utc),
                    discovery_reachable=discovery_reachable,
                    jwks_reachable=jwks_reachable,
                    feed_reachable=feed_reachable,
                    last_event_position=last_event_position,
                    round_trip_ms=round_trip_ms if round_trip_ms is None else max(0, round_trip_ms),
                    health_status=health_status,
                    compatibility_status=compatibility_status,
                    error_code=error_code[:64] if error_code else None,
                    error_detail=safe_detail,
                    created_at=datetime.now(timezone.utc),
                )
            )
        if session is not None:
            _add_row(session)
            return
        with self.db.transaction() as local_session:
            _add_row(local_session)

    def sync_peer(self, *, peer_id: uuid.UUID, trigger_type: str, max_seconds: int) -> SyncResultResponse:
        if not self.settings.inbound_enabled:
            raise FederationError("federation-inbound-disabled", "Federation inbound synchronization is disabled.")
        started = datetime.now(timezone.utc)
        stats = _SyncStats()
        attempt_id = uuid.uuid4()
        lease: ClaimedLease | None = None
        phase = "discovery"
        attempted_remote = False
        peer_node_id_for_health: str | None = None
        last_position_for_health: int | None = None
        discovery_reachable = False
        jwks_reachable = False
        feed_reachable = False
        try:
            lease = self._claim_lease(peer_id=peer_id, trigger_type=trigger_type)
            if lease is None:
                if trigger_type == "manual":
                    raise FederationError("already-running", "Synchronization already running for this peer.")
                return SyncResultResponse(
                    status="already-running",
                    pagesProcessed=0,
                    eventsProcessed=0,
                    importedRecords=0,
                    detail="Synchronization already running for this peer.",
                )
            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                peer_node_id_for_health = peer.peer_node_id
                if peer.archived_at is not None:
                    raise FederationError("peer-archived", "Peer is archived.")
                if peer.trust_status != "trusted" or not peer.sync_enabled:
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
                now = datetime.now(timezone.utc)
                if peer.suspension_reason and (peer.suspended_until is None or peer.suspended_until > now):
                    raise FederationError("peer-suspended", "Peer is administratively suspended.")
                gate = self.circuit.evaluate_gate(peer)
                if gate.transitioned:
                    self._write_operational_audit(
                        action=AuditAction.SYNC_CIRCUIT_HALF_OPENED,
                        peer_id=peer_id,
                        target_id=str(peer_id),
                        outcome=AuditOutcome.SUCCESS,
                        actor_id="admin" if trigger_type == "manual" else None,
                        details={"state": gate.state.value},
                        session=session,
                    )
                if not gate.allowed:
                    if gate.reason == "circuit-open-admin-reset":
                        raise FederationError("circuit-open-admin-reset", "Peer circuit is open and requires admin reset.")
                    raise FederationError("circuit-open", "Peer circuit is open and backoff has not elapsed.")
                allowed_hostnames, allowed_cidrs = self.peer_service._combined_allowlists(
                    peer_allowed_hostnames=peer.allowed_hostnames,
                    peer_allowed_cidrs=peer.allowed_cidrs,
                )
                cursor_row = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one_or_none()
                if cursor_row is None:
                    cursor_row = FederationPeerCursor(
                        id=uuid.uuid4(),
                        peer_id=peer_id,
                        cursor=None,
                        last_remote_position=0,
                        synced_at=None,
                        updated_at=started,
                    )
                    session.add(cursor_row)
                stats.cursor_before = cursor_row.cursor
                session.add(
                    FederationSyncAttempt(
                        id=attempt_id,
                        peer_id=peer_id,
                        started_at=started,
                        status="running",
                        trigger_type=trigger_type,
                        pages_processed=0,
                        events_processed=0,
                        cursor_before=cursor_row.cursor,
                        created_at=started,
                    )
                )
                peer.last_sync_attempt_at = started
                peer.last_sync_status = "running"
                peer.updated_at = started

            if trigger_type == "manual":
                self._write_operational_audit(
                    action=AuditAction.SYNC_MANUAL_TRIGGERED,
                    peer_id=peer_id,
                    target_id=str(peer_id),
                    outcome=AuditOutcome.SUCCESS,
                    actor_id="admin",
                )

            attempted_remote = True
            self._refresh_peer_verification_state(
                peer_id=peer_id,
                allowlists=(allowed_hostnames, allowed_cidrs),
                trigger_type=trigger_type,
            )
            discovery_reachable = True
            jwks_reachable = True

            request_cursor = stats.cursor_before
            committed_resume = stats.cursor_before
            while True:
                if (datetime.now(timezone.utc) - started).total_seconds() > min(max_seconds, self.settings.sync_max_duration_seconds):
                    raise FederationError("sync-timeout", "Synchronization exceeded maximum allowed duration.")
                phase = "changes"
                page = self._fetch_changes_page(
                    peer_id=peer_id,
                    since=request_cursor,
                    allowed_hostnames=allowed_hostnames,
                    allowed_cidrs=allowed_cidrs,
                )
                feed_reachable = True
                phase = "records"
                batch_result = self._process_page(
                    peer_id=peer_id,
                    page=page,
                    allowed_hostnames=allowed_hostnames,
                    allowed_cidrs=allowed_cidrs,
                    lease=lease,
                )
                stats.pages_processed += 1
                stats.events_processed += batch_result[0]
                stats.imported_records += batch_result[1]
                committed_resume = page.resumeCursor
                stats.cursor_after = committed_resume
                if batch_result[2] is not None:
                    last_position_for_health = batch_result[2]
                if not page.hasMore:
                    break
                if not page.nextCursor:
                    raise FederationError("invalid-cursor", "Peer returned hasMore=true without nextCursor.")
                request_cursor = page.nextCursor

            with self.db.transaction() as session:
                peer = session.execute(
                    select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                ).scalar_one()
                circuit_closed = self.circuit.mark_success(peer)
                if circuit_closed:
                    self._write_operational_audit(
                        action=AuditAction.SYNC_CIRCUIT_CLOSED,
                        peer_id=peer_id,
                        target_id=str(peer_id),
                        outcome=AuditOutcome.SUCCESS,
                        actor_id="admin" if trigger_type == "manual" else None,
                        session=session,
                    )
                peer.last_sync_success_at = datetime.now(timezone.utc)
                peer.last_sync_status = "complete"
                peer.last_sync_error_code = None
                peer.last_sync_error_detail = None
                peer.updated_at = datetime.now(timezone.utc)

                attempt = session.execute(select(FederationSyncAttempt).where(FederationSyncAttempt.id == attempt_id)).scalar_one()
                attempt.status = "complete"
                attempt.pages_processed = stats.pages_processed
                attempt.events_processed = stats.events_processed
                attempt.cursor_after = committed_resume
                attempt.completed_at = datetime.now(timezone.utc)
            if peer_node_id_for_health is not None:
                elapsed_ms = max(0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000))
                self._record_health_snapshot(
                    peer_id=peer_id,
                    peer_node_id=peer_node_id_for_health,
                    discovery_reachable=discovery_reachable,
                    jwks_reachable=jwks_reachable,
                    feed_reachable=feed_reachable,
                    last_event_position=last_position_for_health,
                    round_trip_ms=elapsed_ms,
                    health_status="healthy",
                    compatibility_status="unchecked",
                    error_code=None,
                    error_detail=None,
                )
            return SyncResultResponse(
                status="complete",
                pagesProcessed=stats.pages_processed,
                eventsProcessed=stats.events_processed,
                importedRecords=stats.imported_records,
                cursorBefore=stats.cursor_before,
                cursorAfter=stats.cursor_after,
            )
        except FederationError as exc:
            classification = self.circuit.classify_failure(exc, phase=phase)
            if trigger_type == "scheduled" and exc.code in {"peer-suspended", "circuit-open", "circuit-open-admin-reset", "peer-disabled", "peer-archived"}:
                failed_status = "skipped"
            else:
                failed_status = "partial" if stats.pages_processed > 0 else "failed"
            if classification.kind in {"transient", "permanent"}:
                with self.db.transaction() as session:
                    peer = session.execute(
                        select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id).with_for_update()
                    ).scalar_one_or_none()
                    if peer is not None:
                        new_state = self.circuit.mark_failure(peer, classification=classification)
                        if new_state == CircuitState.OPEN:
                            self._write_operational_audit(
                                action=AuditAction.SYNC_CIRCUIT_OPENED,
                                peer_id=peer_id,
                                target_id=str(peer_id),
                                outcome=AuditOutcome.SUCCESS,
                                actor_id="admin" if trigger_type == "manual" else None,
                                reason=classification.reason.value if classification.reason else None,
                                session=session,
                            )
            self._finalize_sync_attempt(
                peer_id=peer_id,
                attempt_id=attempt_id,
                status=failed_status,
                error=exc,
                stats=stats,
            )
            if attempted_remote and peer_node_id_for_health is not None:
                elapsed_ms = max(0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000))
                self._record_health_snapshot(
                    peer_id=peer_id,
                    peer_node_id=peer_node_id_for_health,
                    discovery_reachable=discovery_reachable,
                    jwks_reachable=jwks_reachable,
                    feed_reachable=feed_reachable,
                    last_event_position=last_position_for_health,
                    round_trip_ms=elapsed_ms,
                    health_status="unreachable" if exc.code in {"remote-unreachable", "remote-server-error", "remote-tls-error"} else "degraded",
                    compatibility_status="unknown",
                    error_code=exc.code,
                    error_detail=_safe_health_error_detail(exc),
                )
            if trigger_type == "manual" and exc.code in {"peer-disabled", "peer-suspended", "circuit-open", "circuit-open-admin-reset", "peer-archived", "already-running"}:
                raise
            return SyncResultResponse(
                status=failed_status,
                pagesProcessed=stats.pages_processed,
                eventsProcessed=stats.events_processed,
                importedRecords=stats.imported_records,
                cursorBefore=stats.cursor_before,
                cursorAfter=stats.cursor_after,
                detail=f"{exc.code}: {exc.detail}",
            )
        except Exception as exc:
            logger.exception("Unexpected failure while synchronizing peer %s", peer_id)
            self._finalize_sync_attempt(
                peer_id=peer_id,
                attempt_id=attempt_id,
                status="failed",
                error=FederationError("sync-internal-error", f"{type(exc).__name__}: {str(exc)[:200]}"),
                stats=stats,
            )
            raise
        except (KeyboardInterrupt, SystemExit):
            self._finalize_sync_attempt(
                peer_id=peer_id,
                attempt_id=attempt_id,
                status="failed",
                error=FederationError("sync-cancelled", "Synchronization cancelled during graceful shutdown."),
                stats=stats,
            )
            raise
        finally:
            if lease is not None:
                try:
                    self._release_lease(lease)
                except Exception:
                    logger.exception("Failed to release sync lease for peer %s", peer_id)

    def sync_all_trusted_peers_once(self, *, max_seconds_per_peer: int) -> list[tuple[uuid.UUID, SyncResultResponse]]:
        with self.db.transaction() as session:
            peers = (
                session.execute(
                    select(FederationTrustedPeer.id).where(
                        FederationTrustedPeer.trust_status == "trusted",
                        FederationTrustedPeer.sync_enabled.is_(True),
                    )
                )
                .scalars()
                .all()
            )
        results: list[tuple[uuid.UUID, SyncResultResponse]] = []
        for peer_id in peers:
            result = self.sync_peer(peer_id=peer_id, trigger_type="scheduled", max_seconds=max_seconds_per_peer)
            results.append((peer_id, result))
            if result.status in {"failed", "partial"}:
                sleep_for = self._retry_sleep_seconds(attempt_count=1)
                time.sleep(sleep_for)
        return results

    def _fetch_changes_page(self, *, peer_id: uuid.UUID, since: str | None, allowed_hostnames: tuple[str, ...], allowed_cidrs: tuple[str, ...]) -> RemoteChangesResponse:
        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        params = {"limit": str(self.settings.sync_max_events_per_page)}
        key = "since"
        if since:
            params[key] = since
        query = urlencode(params)
        url = f"{peer.base_url.rstrip('/')}/api/v1/federation/changes?{query}"
        try:
            raw = self.remote_client.get_json(
                url,
                limits=_HttpLimits(self.settings.sync_max_changes_bytes, "application/json"),
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
        except FederationError:
            raise
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote changes page failed validation.") from exc
        except Exception as exc:
            raise FederationError("remote-unreachable", "Failed to retrieve peer changes page.") from exc
        try:
            model = RemoteChangesResponse.model_validate(raw)
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote changes page failed validation.") from exc
        if len(model.events) > self.settings.sync_max_events_per_page:
            raise FederationError("remote-too-many-events", "Peer returned more events than configured maximum.")
        return model

    def _fetch_record(self, *, peer: FederationTrustedPeer, canonical_id: str, allowed_hostnames: tuple[str, ...], allowed_cidrs: tuple[str, ...]) -> RemoteRecordResponse:
        encoded = encode_canonical_id(canonical_id)
        record_url = f"{peer.base_url.rstrip('/')}/api/v1/federation/records/{encoded}"
        try:
            raw = self.remote_client.get_json(
                record_url,
                limits=_HttpLimits(self.settings.sync_max_record_bytes, "application/json"),
                allowed_hostnames=allowed_hostnames,
                allowed_cidrs=allowed_cidrs,
            )
        except FederationError:
            raise
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote record response failed validation.") from exc
        except Exception as exc:
            raise FederationError("remote-unreachable", "Failed to retrieve peer record response.") from exc
        try:
            model = RemoteRecordResponse.model_validate(raw)
        except ValidationError as exc:
            raise FederationError("remote-schema-invalid", "Remote record response failed validation.") from exc
        return model

    def _process_page(
        self,
        *,
        peer_id: uuid.UUID,
        page: RemoteChangesResponse,
        allowed_hostnames: tuple[str, ...],
        allowed_cidrs: tuple[str, ...],
        lease: ClaimedLease,
    ) -> tuple[int, int, int | None]:
        events_processed = 0
        imported = 0
        latest_position: int | None = None
        current_item: Any | None = None
        try:
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                cursor_row = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
                verification_now = session.execute(select(func.now())).scalar_one()
                trusted_keys = (
                    session.execute(
                        select(FederationPeerSigningKey).where(
                            FederationPeerSigningKey.peer_id == peer_id,
                        )
                    )
                    .scalars()
                    .all()
                )
                expected_last = cursor_row.last_remote_position or 0
            key_map = {item.kid: item for item in trusted_keys}
            verified_events: list[tuple[Any, Any, RemoteRecordResponse | None, frozenset[str]]] = []
            for item in page.events:
                current_item = item
                self._validate_event(item=item, peer=peer, key_map=key_map, verification_now=verification_now)
                payload = item.payload
                if payload.generatedAt > datetime.now(timezone.utc) + timedelta(seconds=self.settings.sync_max_future_seconds):
                    raise FederationError("event-future-time", "Event generatedAt is too far in the future.")
                position = payload.eventPosition
                if position <= expected_last:
                    existing = self._find_inbound_event(peer.peer_node_id, payload.eventId, position)
                    if existing is None:
                        raise FederationError("event-order", "Event position decreased unexpectedly.")
                    if (
                        existing.remote_event_id == uuid.UUID(payload.eventId)
                        and existing.signed_payload_digest_sha256 == item.signed.digestSha256
                    ):
                        continue
                    raise FederationError("event-replay-mismatch", "Existing event replay does not match previously accepted content.")
                expected_last = position
                remote_record: RemoteRecordResponse | None = None
                referenced_kids: set[str] = {item.signed.signature.kid}
                if payload.operation == "upsert":
                    remote_record = self._fetch_record(
                        peer=peer,
                        canonical_id=payload.record.canonicalId,
                        allowed_hostnames=allowed_hostnames,
                        allowed_cidrs=allowed_cidrs,
                    )
                    self._validate_record_response(
                        remote_record=remote_record,
                        key_map=key_map,
                        peer=peer,
                        payload=payload,
                        verification_now=verification_now,
                    )
                    referenced_kids.add(remote_record.signed.signature.kid)
                verified_events.append((item.payload, item.signed, remote_record, frozenset(referenced_kids)))

            with self.db.transaction() as session:
                still_owned = self.lease_repo.verify_still_owned_sync(
                    session,
                    peer_id=peer_id,
                    owner_instance_id=lease.owner_instance_id,
                    claimed_fencing_token=lease.fencing_token,
                )
                if not still_owned:
                    raise FederationError("sync-lease-stale", "Synchronization lease is stale; page commit aborted.")

                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                cursor_row = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
                commit_verification_now = session.execute(select(func.now())).scalar_one()
                commit_referenced_kids = {kid for _payload, _signed, _remote_record, kids in verified_events for kid in kids}
                commit_key_map = self._load_referenced_signing_keys_for_commit(
                    session,
                    peer_id=peer_id,
                    referenced_kids=commit_referenced_kids,
                )
                for kid in sorted(commit_referenced_kids):
                    self._assert_commit_key_eligible(
                        kid=kid,
                        key_row=commit_key_map.get(kid),
                        commit_verification_now=commit_verification_now,
                    )

                for payload, signed, remote_record, _kids in verified_events:
                    event_id = uuid.UUID(payload.eventId)
                    existing = session.execute(
                        select(FederationInboundEvent).where(
                            FederationInboundEvent.authority_node_id == payload.record.authorityNodeId,
                            FederationInboundEvent.remote_event_id == event_id,
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        if existing.signed_payload_digest_sha256 != signed.digestSha256:
                            raise FederationError("event-id-collision", "Event ID collision with different digest.")
                        continue
                    existing_pos = session.execute(
                        select(FederationInboundEvent).where(
                            FederationInboundEvent.authority_node_id == payload.record.authorityNodeId,
                            FederationInboundEvent.remote_event_position == payload.eventPosition,
                        )
                    ).scalar_one_or_none()
                    if existing_pos is not None and (
                        existing_pos.remote_event_id != event_id or existing_pos.signed_payload_digest_sha256 != signed.digestSha256
                    ):
                        raise FederationError("event-position-collision", "Remote event position was reused with different content.")
                    self._apply_verified_event(
                        session=session,
                        peer=peer,
                        payload=payload,
                        signed_digest=signed.digestSha256,
                        signature_kid=signed.signature.kid,
                        signature_alg=signed.signature.alg,
                        signature_value=signed.signature.value,
                        remote_record=remote_record,
                    )
                    events_processed += 1
                    latest_position = payload.eventPosition
                    if payload.operation == "upsert":
                        imported += 1

                cursor_row.cursor = page.resumeCursor
                if latest_position is not None:
                    cursor_row.last_remote_position = latest_position
                cursor_row.synced_at = datetime.now(timezone.utc)
                cursor_row.updated_at = datetime.now(timezone.utc)
                try:
                    self.lease_repo.renew_sync(
                        session,
                        peer_id=peer_id,
                        owner_instance_id=lease.owner_instance_id,
                        fencing_token=lease.fencing_token,
                        duration_seconds=self.settings.sync_lease_renewal_seconds,
                    )
                except LeaseConflictError as exc:
                    raise FederationError("sync-lease-stale", "Synchronization lease is stale; page commit aborted.") from exc
            return events_processed, imported, latest_position
        except FederationError as exc:
            if current_item is not None and exc.code != "sync-lease-stale":
                self._persist_rejection(peer_id=peer_id, item=current_item, error=exc)
            raise

    @staticmethod
    def _assert_commit_key_eligible(
        *,
        kid: str,
        key_row: FederationPeerSigningKey | None,
        commit_verification_now: datetime,
    ) -> None:
        if key_row is None:
            raise FederationError("unknown-signing-key", "Signing key is not trusted.")
        if key_row.key_status == "retired":
            raise FederationError("retired-signing-key", "Signing key is retired and not eligible for new inbound synchronization.")
        if key_row.key_status == "revoked":
            raise FederationError("revoked-signing-key", "Signing key is revoked.")
        if key_row.key_status != "active":
            raise FederationError("unknown-signing-key", "Signing key is not trusted.")
        if key_row.valid_from is not None and key_row.valid_from > commit_verification_now:
            raise FederationError("signing-key-not-yet-valid", "Signing key is not yet valid for new inbound synchronization.")
        if key_row.valid_until is not None and commit_verification_now >= key_row.valid_until:
            raise FederationError("signing-key-expired", "Signing key has expired for new inbound synchronization.")

    @staticmethod
    def _load_referenced_signing_keys_for_commit(
        session: Session,
        *,
        peer_id: uuid.UUID,
        referenced_kids: set[str],
    ) -> dict[str, FederationPeerSigningKey]:
        if not referenced_kids:
            return {}
        rows = (
            session.execute(
                select(FederationPeerSigningKey)
                .where(
                    FederationPeerSigningKey.peer_id == peer_id,
                    FederationPeerSigningKey.kid.in_(sorted(referenced_kids)),
                )
                .with_for_update()
            )
            .scalars()
            .all()
        )
        return {row.kid: row for row in rows}

    def _verify_peer_key_signature(
        self,
        *,
        payload: Any,
        signed: Any,
        key_map: dict[str, FederationPeerSigningKey],
        purpose: PeerKeyVerificationPurpose,
        verification_now: datetime | None = None,
    ) -> PeerKeyVerificationResult:
        if signed.signature.alg != "EdDSA":
            return PeerKeyVerificationResult(
                signature_valid=False,
                key_found=False,
                trust_status="unknown",
                eligible_for_application=False,
                rejection_reason="invalid-signature-alg",
            )

        trusted_key = key_map.get(signed.signature.kid)
        if trusted_key is None:
            return PeerKeyVerificationResult(
                signature_valid=False,
                key_found=False,
                trust_status="unknown",
                eligible_for_application=False,
                rejection_reason="unknown-signing-key",
            )

        trust_status = trusted_key.key_status
        payload_bytes = canonicalize_to_bytes(payload.model_dump(mode="json"))
        digest = sha256_hex(payload_bytes)
        if not hmac.compare_digest(digest, signed.digestSha256):
            return PeerKeyVerificationResult(
                signature_valid=False,
                key_found=True,
                trust_status=trust_status,
                eligible_for_application=False,
                rejection_reason="digest-mismatch",
            )
        try:
            key = Ed25519PublicKey.from_public_bytes(_b64url_decode(trusted_key.x))
            key.verify(_b64url_decode(signed.signature.value), payload_bytes)
        except Exception:
            return PeerKeyVerificationResult(
                signature_valid=False,
                key_found=True,
                trust_status=trust_status,
                eligible_for_application=False,
                rejection_reason="invalid-signature",
            )

        if purpose == PeerKeyVerificationPurpose.NEW_INBOUND_EVENT:
            if trust_status == "retired":
                return PeerKeyVerificationResult(
                    signature_valid=True,
                    key_found=True,
                    trust_status=trust_status,
                    eligible_for_application=False,
                    rejection_reason="retired-signing-key",
                )
            if trust_status == "revoked":
                return PeerKeyVerificationResult(
                    signature_valid=True,
                    key_found=True,
                    trust_status=trust_status,
                    eligible_for_application=False,
                    rejection_reason="revoked-signing-key",
                )
            if trust_status != "active":
                return PeerKeyVerificationResult(
                    signature_valid=True,
                    key_found=True,
                    trust_status=trust_status,
                    eligible_for_application=False,
                    rejection_reason="unknown-signing-key",
                )
            if verification_now is None:
                raise FederationError("sync-internal-error", "Missing database verification time for key validity checks.")
            if trusted_key.valid_from is not None and trusted_key.valid_from > verification_now:
                return PeerKeyVerificationResult(
                    signature_valid=True,
                    key_found=True,
                    trust_status=trust_status,
                    eligible_for_application=False,
                    rejection_reason="signing-key-not-yet-valid",
                )
            if trusted_key.valid_until is not None and verification_now >= trusted_key.valid_until:
                return PeerKeyVerificationResult(
                    signature_valid=True,
                    key_found=True,
                    trust_status=trust_status,
                    eligible_for_application=False,
                    rejection_reason="signing-key-expired",
                )
            return PeerKeyVerificationResult(
                signature_valid=True,
                key_found=True,
                trust_status=trust_status,
                eligible_for_application=True,
                rejection_reason=None,
            )

        # HISTORICAL_EVIDENCE performs cryptographic verification only. It never
        # authorizes imports or state mutation and does not apply temporal key
        # validity windows.
        return PeerKeyVerificationResult(
            signature_valid=True,
            key_found=True,
            trust_status=trust_status,
            eligible_for_application=False,
            rejection_reason=None,
        )

    def _validate_event(
        self,
        *,
        item: Any,
        peer: FederationTrustedPeer,
        key_map: dict[str, FederationPeerSigningKey],
        verification_now: datetime,
    ) -> None:
        verification = self._verify_peer_key_signature(
            payload=item.payload,
            signed=item.signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=verification_now,
        )
        if not verification.signature_valid or not verification.eligible_for_application:
            reason = verification.rejection_reason or "invalid-signature"
            details = {
                "invalid-signature-alg": "Event signature algorithm must be EdDSA.",
                "unknown-signing-key": "Event signing key is not trusted.",
                "retired-signing-key": "Event signing key is retired and not eligible for new inbound synchronization.",
                "revoked-signing-key": "Event signing key is revoked.",
                "signing-key-not-yet-valid": "Event signing key is not yet valid for new inbound synchronization.",
                "signing-key-expired": "Event signing key has expired for new inbound synchronization.",
                "digest-mismatch": "Event digest does not match payload.",
                "invalid-signature": "Event signature verification failed.",
            }
            raise FederationError(reason, details.get(reason, "Event signature verification failed."))
        if item.payload.nodeId != peer.peer_node_id:
            raise FederationError("peer-node-mismatch", "Event nodeId does not match pinned peer node ID.")
        if item.payload.record.authorityNodeId != peer.peer_node_id:
            raise FederationError("authority-mismatch", "Event authority does not match pinned peer node ID.")
        if item.payload.eventPosition <= 0:
            raise FederationError("invalid-event-position", "Event position must be positive.")
        identity = build_canonical_license_identity(
            authority_node_id=item.payload.record.authorityNodeId,
            local_id=item.payload.record.localId,
            version=item.payload.record.version,
        )
        if identity.canonicalId != item.payload.record.canonicalId:
            raise FederationError("invalid-canonical-id", "Event canonical identifier is inconsistent.")
        if canonical_json_sha256_hex(item.payload.record.payload) != item.payload.record.payloadDigestSha256:
            raise FederationError("record-payload-digest-mismatch", "Embedded event record digest is invalid.")
        if len(canonicalize_to_bytes(item.payload.record.payload)) > self.settings.sync_max_embedded_payload_bytes:
            raise FederationError("embedded-payload-too-large", "Embedded record payload is too large.")

    def _validate_record_response(
        self,
        *,
        remote_record: RemoteRecordResponse,
        key_map: dict[str, FederationPeerSigningKey],
        peer: FederationTrustedPeer,
        payload: Any,
        verification_now: datetime,
    ) -> None:
        verification = self._verify_peer_key_signature(
            payload=remote_record.record,
            signed=remote_record.signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=verification_now,
        )
        if not verification.signature_valid or not verification.eligible_for_application:
            reason = verification.rejection_reason or "invalid-signature"
            details = {
                "invalid-signature-alg": "Record signature algorithm must be EdDSA.",
                "unknown-signing-key": "Record signing key is not trusted.",
                "retired-signing-key": "Record signing key is retired and not eligible for new inbound synchronization.",
                "revoked-signing-key": "Record signing key is revoked.",
                "signing-key-not-yet-valid": "Record signing key is not yet valid for new inbound synchronization.",
                "signing-key-expired": "Record signing key has expired for new inbound synchronization.",
                "digest-mismatch": "Record digest mismatch.",
                "invalid-signature": "Record signature verification failed.",
            }
            raise FederationError(reason, details.get(reason, "Record signature verification failed."))
        if remote_record.record.nodeId != peer.peer_node_id:
            raise FederationError("peer-node-mismatch", "Record nodeId does not match pinned peer node ID.")
        if remote_record.record.authorityNodeId != peer.peer_node_id:
            raise FederationError("authority-mismatch", "Record authority does not match pinned peer node ID.")
        if remote_record.record.canonicalId != payload.record.canonicalId:
            raise FederationError("event-record-mismatch", "Record canonical ID does not match event payload.")
        if remote_record.record.localId != payload.record.localId:
            raise FederationError("event-record-mismatch", "Record local ID does not match event payload.")
        if remote_record.record.version != payload.record.version:
            raise FederationError("event-record-mismatch", "Record version does not match event payload.")
        if remote_record.record.publishedAt != payload.record.publishedAt:
            raise FederationError("event-record-mismatch", "Record publishedAt does not match event payload.")
        if remote_record.record.payloadDigestSha256 != payload.record.payloadDigestSha256:
            raise FederationError("event-record-mismatch", "Record payload digest does not match event payload.")
        if remote_record.record.payload != payload.record.payload:
            raise FederationError("event-record-mismatch", "Record payload does not match event payload.")

    def _find_inbound_event(
        self,
        authority_node_id: str,
        event_id: str,
        event_position: int,
    ) -> FederationInboundEvent | None:
        with self.db.transaction() as session:
            return session.execute(
                select(FederationInboundEvent).where(
                    FederationInboundEvent.authority_node_id == authority_node_id,
                    FederationInboundEvent.remote_event_id == uuid.UUID(event_id),
                    FederationInboundEvent.remote_event_position == event_position,
                )
            ).scalar_one_or_none()

    def _apply_verified_event(
        self,
        *,
        session: Session,
        peer: FederationTrustedPeer,
        payload: Any,
        signed_digest: str,
        signature_kid: str,
        signature_alg: str,
        signature_value: str,
        remote_record: RemoteRecordResponse | None,
    ) -> None:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == payload.record.canonicalId)).scalar_one_or_none()
        if record is not None and record.is_authoritative:
            raise FederationError("authoritative-collision", "Imported record conflicts with local authoritative record.")

        now = datetime.now(timezone.utc)
        if payload.operation == "upsert":
            if remote_record is None:
                raise FederationError("missing-record", "Upsert event requires verified record response.")
            if record is None:
                identity = build_canonical_license_identity(
                    authority_node_id=payload.record.authorityNodeId,
                    local_id=payload.record.localId,
                    version=payload.record.version,
                )
                record = FederationRecord(
                    id=uuid.uuid4(),
                    authority_node_id=payload.record.authorityNodeId,
                    local_id=payload.record.localId,
                    version=payload.record.version,
                    canonical_id=payload.record.canonicalId,
                    resolving_uuid=uuid.UUID(identity.resolvingUuid),
                    is_authoritative=False,
                    payload=payload.record.payload,
                    payload_digest_sha256=payload.record.payloadDigestSha256,
                    published_at=payload.record.publishedAt,
                    imported_from_peer_id=peer.id,
                    lifecycle_state="published",
                    source_record_url=f"{peer.base_url}/api/v1/federation/records/{encode_canonical_id(payload.record.canonicalId)}",
                    source_event_id=uuid.UUID(payload.eventId),
                    source_event_position=payload.eventPosition,
                    source_signature_kid=signature_kid,
                    source_signed_payload_digest_sha256=signed_digest,
                    verification_status="verified",
                    last_verified_at=now,
                    created_at=now,
                    updated_at=now,
                )
                session.add(record)
            else:
                if record.payload_digest_sha256 != payload.record.payloadDigestSha256:
                    self._record_conflict(
                        session=session,
                        peer=peer,
                        record_key=payload.record.canonicalId,
                        reason="Immutable imported digest mismatch for canonical ID.",
                    )
                    raise FederationError("immutable-digest-mismatch", "Imported canonical ID has conflicting immutable digest.")
                record.lifecycle_state = "published"
                record.source_event_id = uuid.UUID(payload.eventId)
                record.source_event_position = payload.eventPosition
                record.source_signature_kid = signature_kid
                record.source_signed_payload_digest_sha256 = signed_digest
                record.verification_status = "verified"
                record.last_verified_at = now
                record.updated_at = now
            record.materialized_generation = payload.eventPosition
            self._sync_resolution_aliases(session=session, record=record, peer=peer, payload=payload)
            session.add(
                FederationRecordProvenance(
                    id=uuid.uuid4(),
                    record_id=record.id,
                    source_node_id=peer.peer_node_id,
                    source_uri=record.source_record_url,
                    source_digest_sha256=payload.record.payloadDigestSha256,
                    provenance_type="imported",
                    imported_at=now,
                    asserted_at=now,
                    metadata_json={
                        "sourceEventId": payload.eventId,
                        "sourceEventPosition": payload.eventPosition,
                        "signatureKid": signature_kid,
                        "verificationStatus": "verified",
                    },
                )
            )
        elif payload.operation == "deprecate":
            if record is None:
                raise FederationError("missing-record", "Deprecate event received before imported upsert record.")
            if record.lifecycle_state == "tombstoned":
                raise FederationError("invalid-state-transition", "Cannot deprecate an already tombstoned imported record.")
            record.lifecycle_state = "deprecated"
            record.last_verified_at = now
            record.updated_at = now
            record.materialized_generation = payload.eventPosition
        elif payload.operation == "tombstone":
            if record is None:
                raise FederationError("missing-record", "Tombstone event received before imported upsert record.")
            record.lifecycle_state = "tombstoned"
            record.last_verified_at = now
            record.updated_at = now
            record.materialized_generation = payload.eventPosition
        else:
            raise FederationError("invalid-operation", "Unsupported remote operation.")

        session.add(
            FederationInboundEvent(
                id=uuid.uuid4(),
                source_peer_id=peer.id,
                authority_node_id=payload.record.authorityNodeId,
                remote_event_id=uuid.UUID(payload.eventId),
                remote_event_position=payload.eventPosition,
                remote_operation=payload.operation,
                signed_payload=payload.model_dump(mode="json"),
                signed_payload_digest_sha256=signed_digest,
                signature_kid=signature_kid,
                signature_alg=signature_alg,
                signature_base64url=signature_value,
                generated_at=payload.generatedAt,
                received_at=now,
                processing_status="accepted",
                record_canonical_id=payload.record.canonicalId,
                record_payload_digest_sha256=payload.record.payloadDigestSha256,
            )
        )
        self.rdf_outbox.enqueue_record_jobs(session, record, operation=payload.operation)

    def _persist_rejection(self, *, peer_id: uuid.UUID, item: Any, error: FederationError) -> None:
        now = datetime.now(timezone.utc)
        with self.db.transaction() as session:
            existing_event = session.execute(
                select(FederationInboundEvent).where(
                    FederationInboundEvent.authority_node_id == item.payload.record.authorityNodeId,
                    FederationInboundEvent.remote_event_id == uuid.UUID(item.payload.eventId),
                )
            ).scalar_one_or_none()
            if existing_event is not None and existing_event.signed_payload_digest_sha256 == item.signed.digestSha256:
                return
            existing_pos = session.execute(
                select(FederationInboundEvent).where(
                    FederationInboundEvent.authority_node_id == item.payload.record.authorityNodeId,
                    FederationInboundEvent.remote_event_position == item.payload.eventPosition,
                )
            ).scalar_one_or_none()
            if existing_pos is not None and existing_pos.signed_payload_digest_sha256 == item.signed.digestSha256:
                return
            can_store_rejection = existing_pos is None and existing_event is None
            if can_store_rejection:
                session.add(
                    FederationInboundEvent(
                        id=uuid.uuid4(),
                        source_peer_id=peer_id,
                        authority_node_id=item.payload.record.authorityNodeId,
                        remote_event_id=uuid.UUID(item.payload.eventId),
                        remote_event_position=item.payload.eventPosition,
                        remote_operation=item.payload.operation,
                        signed_payload=item.signed.model_dump(mode="json"),
                        signed_payload_digest_sha256=item.signed.digestSha256,
                        signature_kid=item.signed.signature.kid,
                        signature_alg=item.signed.signature.alg,
                        signature_base64url=item.signed.signature.value,
                        generated_at=item.payload.generatedAt,
                        received_at=now,
                        processing_status="rejected",
                        record_canonical_id=item.payload.record.canonicalId,
                        record_payload_digest_sha256=item.payload.record.payloadDigestSha256,
                        error_code=error.code,
                        error_detail=error.detail[:256],
                    )
                )
            if error.code in {"authoritative-collision", "immutable-digest-mismatch", "event-position-collision", "event-id-collision", "event-order"}:
                conflict = session.execute(
                    select(FederationConflictRecord).where(
                        FederationConflictRecord.record_key == item.payload.record.canonicalId,
                        FederationConflictRecord.remote_peer_id == peer_id,
                    )
                ).scalar_one_or_none()
                if conflict is None:
                    session.add(
                        FederationConflictRecord(
                            id=uuid.uuid4(),
                            record_key=item.payload.record.canonicalId,
                            local_record_id=None,
                            remote_peer_id=peer_id,
                            remote_record_ref=item.payload.record.canonicalId,
                            reason=error.detail[:1024],
                            status="open",
                            created_at=now,
                        )
                    )
                return
            if existing_pos is not None or existing_event is not None:
                conflict = session.execute(
                    select(FederationConflictRecord).where(
                        FederationConflictRecord.record_key == item.payload.record.canonicalId,
                        FederationConflictRecord.remote_peer_id == peer_id,
                    )
                ).scalar_one_or_none()
                if conflict is None:
                    session.add(
                        FederationConflictRecord(
                            id=uuid.uuid4(),
                            record_key=item.payload.record.canonicalId,
                            local_record_id=None,
                            remote_peer_id=peer_id,
                            remote_record_ref=item.payload.record.canonicalId,
                            reason=error.detail[:1024],
                            status="open",
                            created_at=now,
                        )
                    )
                return

    @staticmethod
    def _record_conflict(session: Session, *, peer: FederationTrustedPeer, record_key: str, reason: str) -> None:
        session.add(
            FederationConflictRecord(
                id=uuid.uuid4(),
                record_key=record_key,
                local_record_id=None,
                remote_peer_id=peer.id,
                remote_record_ref=record_key,
                reason=reason,
                status="open",
                created_at=datetime.now(timezone.utc),
            )
        )

    @staticmethod
    def _normalize_identifier(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    def _upsert_resolution_alias(
        self,
        *,
        session: Session,
        record: FederationRecord,
        alias_value: str,
        alias_kind: str,
        authority_node_id: str | None,
        source_peer: FederationTrustedPeer | None,
        is_authoritative: bool,
    ) -> None:
        normalized = self._normalize_identifier(alias_value)
        if not normalized:
            return
        now = datetime.now(timezone.utc)
        existing = session.execute(
            select(FederationResolutionAlias).where(
                FederationResolutionAlias.normalized_identifier == normalized,
                FederationResolutionAlias.record_id == record.id,
                FederationResolutionAlias.alias_kind == alias_kind,
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                FederationResolutionAlias(
                    id=uuid.uuid4(),
                    normalized_identifier=normalized,
                    alias_value=alias_value,
                    alias_kind=alias_kind,
                    record_id=record.id,
                    authority_node_id=authority_node_id,
                    source_peer_id=source_peer.id if source_peer else None,
                    is_authoritative=is_authoritative,
                    created_at=now,
                    updated_at=now,
                )
            )
            return
        existing.alias_value = alias_value
        existing.authority_node_id = authority_node_id
        existing.source_peer_id = source_peer.id if source_peer else None
        existing.is_authoritative = is_authoritative
        existing.updated_at = now

    def _sync_resolution_aliases(
        self,
        *,
        session: Session,
        record: FederationRecord,
        peer: FederationTrustedPeer | None,
        payload: Any,
    ) -> None:
        self._upsert_resolution_alias(
            session=session,
            record=record,
            alias_value=record.canonical_id,
            alias_kind="canonical",
            authority_node_id=record.authority_node_id,
            source_peer=peer,
            is_authoritative=record.is_authoritative and record.imported_from_peer_id is None,
        )
        if record.source_record_url:
            self._upsert_resolution_alias(
                session=session,
                record=record,
                alias_value=record.source_record_url,
                alias_kind="authority-uri",
                authority_node_id=record.authority_node_id,
                source_peer=peer,
                is_authoritative=False,
            )
        explicit_aliases = payload.record.payload.get("aliases") if hasattr(payload.record, "payload") else None
        if isinstance(explicit_aliases, list):
            for alias in explicit_aliases:
                if isinstance(alias, str) and alias.strip():
                    self._upsert_resolution_alias(
                        session=session,
                        record=record,
                        alias_value=alias,
                        alias_kind="approved-alias",
                        authority_node_id=record.authority_node_id,
                        source_peer=peer,
                        is_authoritative=record.is_authoritative and record.imported_from_peer_id is None,
                    )

    @staticmethod
    def _retry_sleep_seconds(attempt_count: int) -> float:
        base = min(2**attempt_count, 30)
        return float(base) + random.uniform(0, 0.5)

    def status(self) -> AdminStatusResponse:
        with self.db.transaction() as session:
            peers = int(session.execute(select(func.count()).select_from(FederationTrustedPeer)).scalar_one())
            trusted = int(
                session.execute(
                    select(func.count()).select_from(FederationTrustedPeer).where(FederationTrustedPeer.trust_status == "trusted")
                ).scalar_one()
            )
            disabled = int(
                session.execute(
                    select(func.count()).select_from(FederationTrustedPeer).where(FederationTrustedPeer.trust_status != "trusted")
                ).scalar_one()
            )
            imported = int(
                session.execute(
                    select(func.count()).select_from(FederationRecord).where(FederationRecord.is_authoritative.is_(False))
                ).scalar_one()
            )
            accepted = int(
                session.execute(
                    select(func.count()).select_from(FederationInboundEvent).where(FederationInboundEvent.processing_status == "accepted")
                ).scalar_one()
            )
            rejected = int(
                session.execute(
                    select(func.count()).select_from(FederationInboundEvent).where(FederationInboundEvent.processing_status != "accepted")
                ).scalar_one()
            )
        return AdminStatusResponse(
            nodeId=self.settings.node_id,
            federationEnabled=self.settings.enabled,
            inboundEnabled=self.settings.inbound_enabled,
            peers=peers,
            trustedPeers=trusted,
            disabledPeers=disabled,
            importedRecords=imported,
            inboundEventsAccepted=accepted,
            inboundEventsRejected=rejected,
            workerIntervalSeconds=self.settings.worker_interval_seconds,
            maxSyncSeconds=self.settings.worker_max_sync_seconds,
        )
