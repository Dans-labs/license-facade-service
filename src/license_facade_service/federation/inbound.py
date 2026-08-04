from __future__ import annotations

import hashlib
import hmac
import logging
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationConflictRecord,
    FederationInboundEvent,
    FederationPeerAuditLog,
    FederationPeerCursor,
    FederationPeerSigningKey,
    FederationRecord,
    FederationRecordProvenance,
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
    PeerCreateRequest,
    PeerPatchRequest,
    PeerResponse,
    RemoteChangesResponse,
    RemoteDiscoveryResponse,
    RemoteJwksResponse,
    RemoteRecordResponse,
    SyncResultResponse,
)
from src.license_facade_service.federation.json_strict import DuplicateJsonKeyError, loads_json_no_duplicates
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.outbound import FederationError, encode_canonical_id
from src.license_facade_service.federation.security import FederationUrlPolicy, UrlSecurityError

logger = logging.getLogger(__name__)


def ed25519_key_fingerprint_hex(x_b64url: str) -> str:
    raw = _b64url_decode(x_b64url)
    if len(raw) != 32:
        raise FederationError("invalid-peer-key", "Peer key length is invalid for Ed25519.")
    return hashlib.sha256(raw).hexdigest()


def _b64url_decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


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
                    if response.status_code >= 500 and attempt + 1 < attempts:
                        time.sleep(min(self.settings.sync_retry_base_seconds * (2**attempt), self.settings.sync_retry_max_seconds) + random.uniform(0, 0.1))
                        continue
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
                if attempt + 1 < attempts:
                    time.sleep(min(self.settings.sync_retry_base_seconds * (2**attempt), self.settings.sync_retry_max_seconds) + random.uniform(0, 0.1))
                    continue
                raise FederationError("remote-unreachable", "Remote endpoint is unreachable.") from exc
        raise FederationError("remote-unreachable", "Remote endpoint is unreachable.")


class FederationPeerService:
    def __init__(self, db: Database, settings: FederationSettings, remote_client: FederationRemoteClient | None = None):
        self.db = db
        self.settings = settings
        self.remote_client = remote_client or FederationRemoteClient(settings)

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
        return [self._to_peer_response(row) for row in rows], total

    def get_peer(self, peer_id: uuid.UUID) -> PeerResponse:
        with self.db.transaction() as session:
            row = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
            if row is None:
                raise FederationError("peer-not-found", "Trusted peer was not found.")
        return self._to_peer_response(row)

    def list_imported_records(self, peer_id: uuid.UUID) -> ImportedRecordListResponse:
        with self.db.transaction() as session:
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
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
            peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
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
                self._upsert_peer_key(
                    session=session,
                    peer=peer,
                    kid=match.kid,
                    x=match.x,
                    key_status="active",
                    actor=actor,
                )
                peer.expected_key_kid = payload.verificationKey.kid
                peer.expected_key_fingerprint = fingerprint
            peer.updated_at = datetime.now(timezone.utc)
            self._audit(session, peer.id, "peer.updated", actor, payload.model_dump(exclude_none=True))
        return self.get_peer(peer_id)

    def archive_peer(self, *, peer_id: uuid.UUID, actor: str) -> PeerResponse:
        return self.patch_peer(
            peer_id=peer_id,
            payload=PeerPatchRequest(trustStatus="archived", syncEnabled=False),
            actor=actor,
        )

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
    def _to_peer_response(peer: FederationTrustedPeer) -> PeerResponse:
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
    def __init__(self, db: Database, settings: FederationSettings, remote_client: FederationRemoteClient | None = None):
        self.db = db
        self.settings = settings
        self.remote_client = remote_client or FederationRemoteClient(settings)
        self.peer_service = FederationPeerService(db, settings, remote_client=self.remote_client)

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

    def sync_peer(self, *, peer_id: uuid.UUID, trigger_type: str, max_seconds: int) -> SyncResultResponse:
        if not self.settings.inbound_enabled:
            raise FederationError("federation-inbound-disabled", "Federation inbound synchronization is disabled.")
        started = datetime.now(timezone.utc)
        stats = _SyncStats()
        attempt_id = uuid.uuid4()
        lock_key = self._advisory_lock_key(peer_id)
        lock_session = self.db.session_factory()
        try:
            locked = bool(lock_session.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": lock_key}).scalar_one())
            if not locked:
                return SyncResultResponse(
                    status="already-running",
                    pagesProcessed=0,
                    eventsProcessed=0,
                    importedRecords=0,
                    detail="Synchronization already running for this peer.",
                )
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one_or_none()
                if peer is None:
                    raise FederationError("peer-not-found", "Trusted peer was not found.")
                if peer.trust_status != "trusted" or not peer.sync_enabled:
                    raise FederationError("peer-disabled", "Peer is disabled or not trusted.")
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

            self._refresh_peer_verification_state(
                peer_id=peer_id,
                allowlists=(allowed_hostnames, allowed_cidrs),
                trigger_type=trigger_type,
            )

            request_cursor = stats.cursor_before
            committed_resume = stats.cursor_before
            while True:
                if (datetime.now(timezone.utc) - started).total_seconds() > max_seconds:
                    raise FederationError("sync-timeout", "Synchronization exceeded maximum allowed duration.")
                page = self._fetch_changes_page(
                    peer_id=peer_id,
                    since=request_cursor,
                    allowed_hostnames=allowed_hostnames,
                    allowed_cidrs=allowed_cidrs,
                )
                batch_result = self._process_page(
                    peer_id=peer_id,
                    page=page,
                    allowed_hostnames=allowed_hostnames,
                    allowed_cidrs=allowed_cidrs,
                )
                stats.pages_processed += 1
                stats.events_processed += batch_result[0]
                stats.imported_records += batch_result[1]
                committed_resume = page.resumeCursor
                stats.cursor_after = committed_resume
                if not page.hasMore:
                    break
                if not page.nextCursor:
                    raise FederationError("invalid-cursor", "Peer returned hasMore=true without nextCursor.")
                request_cursor = page.nextCursor

            with self.db.transaction() as session:
                cursor_row = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
                cursor_row.cursor = committed_resume
                cursor_row.synced_at = datetime.now(timezone.utc)
                cursor_row.updated_at = datetime.now(timezone.utc)
                if stats.events_processed > 0:
                    latest_position = session.execute(
                        select(func.max(FederationInboundEvent.remote_event_position)).where(FederationInboundEvent.source_peer_id == peer_id)
                    ).scalar_one()
                    cursor_row.last_remote_position = int(latest_position or 0)

                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
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
            return SyncResultResponse(
                status="complete",
                pagesProcessed=stats.pages_processed,
                eventsProcessed=stats.events_processed,
                importedRecords=stats.imported_records,
                cursorBefore=stats.cursor_before,
                cursorAfter=stats.cursor_after,
            )
        except FederationError as exc:
            failed_status = "partial" if stats.pages_processed > 0 else "failed"
            self._finalize_sync_attempt(
                peer_id=peer_id,
                attempt_id=attempt_id,
                status=failed_status,
                error=exc,
                stats=stats,
            )
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
        finally:
            try:
                lock_session.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": lock_key})
                lock_session.commit()
            finally:
                lock_session.close()

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
    ) -> tuple[int, int]:
        events_processed = 0
        imported = 0
        current_item: Any | None = None
        try:
            with self.db.transaction() as session:
                peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                cursor_row = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
                trusted_keys = (
                    session.execute(
                        select(FederationPeerSigningKey).where(
                            FederationPeerSigningKey.peer_id == peer_id,
                            FederationPeerSigningKey.key_status.in_(["active", "retired"]),
                        )
                    )
                    .scalars()
                    .all()
                )
                key_map = {item.kid: item for item in trusted_keys}
                expected_last = cursor_row.last_remote_position or 0
                verified_events: list[tuple[Any, Any, RemoteRecordResponse | None]] = []
                for item in page.events:
                    current_item = item
                    self._validate_event(item=item, peer=peer, key_map=key_map)
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
                    if payload.operation == "upsert":
                        remote_record = self._fetch_record(
                            peer=peer,
                            canonical_id=payload.record.canonicalId,
                            allowed_hostnames=allowed_hostnames,
                            allowed_cidrs=allowed_cidrs,
                        )
                        self._validate_record_response(remote_record=remote_record, key_map=key_map, peer=peer, payload=payload)
                    verified_events.append((item.payload, item.signed, remote_record))

                for payload, signed, remote_record in verified_events:
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
                    if payload.operation == "upsert":
                        imported += 1
                cursor_row.cursor = page.resumeCursor
                if verified_events:
                    cursor_row.last_remote_position = verified_events[-1][0].eventPosition
                cursor_row.synced_at = datetime.now(timezone.utc)
                cursor_row.updated_at = datetime.now(timezone.utc)
            return events_processed, imported
        except FederationError as exc:
            if current_item is not None:
                self._persist_rejection(peer_id=peer_id, item=current_item, error=exc)
            raise

    def _validate_event(self, *, item: Any, peer: FederationTrustedPeer, key_map: dict[str, FederationPeerSigningKey]) -> None:
        if item.signed.signature.alg != "EdDSA":
            raise FederationError("invalid-signature-alg", "Event signature algorithm must be EdDSA.")
        trusted = key_map.get(item.signed.signature.kid)
        if trusted is None:
            raise FederationError("unknown-signing-key", "Event signing key is not trusted.")
        if trusted.key_status == "revoked":
            raise FederationError("revoked-signing-key", "Event signing key is revoked.")
        payload_bytes = canonicalize_to_bytes(item.payload.model_dump(mode="json"))
        digest = sha256_hex(payload_bytes)
        if not hmac.compare_digest(digest, item.signed.digestSha256):
            raise FederationError("digest-mismatch", "Event digest does not match payload.")
        key = Ed25519PublicKey.from_public_bytes(_b64url_decode(trusted.x))
        try:
            key.verify(_b64url_decode(item.signed.signature.value), payload_bytes)
        except Exception as exc:
            raise FederationError("invalid-signature", "Event signature verification failed.") from exc
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
    ) -> None:
        key = key_map.get(remote_record.signed.signature.kid)
        if key is None or key.key_status == "revoked":
            raise FederationError("unknown-signing-key", "Record signing key is not trusted.")
        if remote_record.signed.signature.alg != "EdDSA":
            raise FederationError("invalid-signature-alg", "Record signature algorithm must be EdDSA.")
        bytes_payload = canonicalize_to_bytes(remote_record.record.model_dump(mode="json"))
        digest = sha256_hex(bytes_payload)
        if not hmac.compare_digest(digest, remote_record.signed.digestSha256):
            raise FederationError("digest-mismatch", "Record digest mismatch.")
        try:
            Ed25519PublicKey.from_public_bytes(_b64url_decode(key.x)).verify(
                _b64url_decode(remote_record.signed.signature.value),
                bytes_payload,
            )
        except Exception as exc:
            raise FederationError("invalid-signature", "Record signature verification failed.") from exc
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
        elif payload.operation == "tombstone":
            if record is None:
                raise FederationError("missing-record", "Tombstone event received before imported upsert record.")
            record.lifecycle_state = "tombstoned"
            record.last_verified_at = now
            record.updated_at = now
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
    def _advisory_lock_key(peer_id: uuid.UUID) -> int:
        return int.from_bytes(peer_id.bytes[:8], byteorder="big", signed=True)

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
