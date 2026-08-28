from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import FederationTrustedPeer
from src.license_facade_service.federation.audit import CircuitFailureReason, CircuitState
from src.license_facade_service.federation.outbound import FederationError

FailureKind = Literal["transient", "permanent", "none"]


@dataclass(frozen=True)
class FailureClassification:
    kind: FailureKind
    reason: CircuitFailureReason | None


@dataclass(frozen=True)
class CircuitGateResult:
    allowed: bool
    state: CircuitState
    reason: str | None = None
    transitioned: bool = False


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_jitter() -> float:
    return random.uniform(0.75, 1.25)


class PeerCircuitService:
    """Transient/permanent peer circuit state transitions.

    This service mutates a FederationTrustedPeer row inside caller-managed
    short DB transactions. It never performs sleeps or network I/O.
    """

    def __init__(
        self,
        settings: FederationSettings,
        *,
        now_provider: Callable[[], datetime] = _default_now,
        jitter_provider: Callable[[], float] = _default_jitter,
    ) -> None:
        self.settings = settings
        self._now = now_provider
        self._jitter = jitter_provider

    def classify_failure(self, error: FederationError, *, phase: str) -> FailureClassification:
        code = error.code
        if code in {"sync-lease-conflict", "already-running", "peer-suspended", "peer-disabled", "peer-archived"}:
            return FailureClassification(kind="none", reason=None)

        if code in {"remote-unreachable", "remote-redirect"}:
            return FailureClassification(kind="transient", reason=CircuitFailureReason.NETWORK_UNREACHABLE)
        if code == "remote-tls-error":
            return FailureClassification(kind="transient", reason=CircuitFailureReason.TLS_ERROR)
        if code == "remote-server-error":
            return FailureClassification(kind="transient", reason=CircuitFailureReason.REMOTE_5XX)
        if code == "event-future-time":
            return FailureClassification(kind="transient", reason=CircuitFailureReason.CLOCK_SKEW)
        if code in {"duplicate-json-key", "invalid-remote-json", "remote-schema-invalid"}:
            reason = CircuitFailureReason.DISCOVERY_PARSE_FAILURE if phase == "discovery" else CircuitFailureReason.JWKS_PARSE_FAILURE
            return FailureClassification(kind="transient", reason=reason)

        if code in {
            "invalid-signature",
            "invalid-signature-alg",
            "digest-mismatch",
            "record-payload-digest-mismatch",
            "event-id-collision",
            "event-position-collision",
            "event-replay-mismatch",
        }:
            return FailureClassification(kind="permanent", reason=CircuitFailureReason.SIGNATURE_INVALID)
        if code == "key-collision":
            return FailureClassification(kind="permanent", reason=CircuitFailureReason.KEY_COLLISION)
        if code in {
            "peer-node-mismatch",
            "authority-mismatch",
            "peer-base-url-mismatch",
            "peer-key-mismatch",
            "peer-key-missing",
            "unknown-signing-key",
            "retired-signing-key",
            "signing-key-not-yet-valid",
            "signing-key-expired",
        }:
            return FailureClassification(kind="permanent", reason=CircuitFailureReason.IDENTITY_MISMATCH)
        if code in {"revoked-signing-key"}:
            return FailureClassification(kind="permanent", reason=CircuitFailureReason.REVOKED_KEY_DETECTED)
        if code in {"protocol-incompatible"}:
            return FailureClassification(kind="permanent", reason=CircuitFailureReason.PROTOCOL_INCOMPATIBLE)
        return FailureClassification(kind="none", reason=None)

    def evaluate_gate(self, peer: FederationTrustedPeer) -> CircuitGateResult:
        now = self._now()
        state = CircuitState(peer.circuit_state or "closed")
        if state == CircuitState.CLOSED:
            return CircuitGateResult(allowed=True, state=state)

        if state == CircuitState.OPEN:
            if peer.circuit_requires_admin_reset:
                return CircuitGateResult(allowed=False, state=state, reason="circuit-open-admin-reset")
            if peer.circuit_next_attempt_at and peer.circuit_next_attempt_at > now:
                return CircuitGateResult(allowed=False, state=state, reason="circuit-open-backoff")
            peer.circuit_state = CircuitState.HALF_OPEN.value
            peer.circuit_half_open_probe_count = 0
            peer.updated_at = now
            return CircuitGateResult(allowed=True, state=CircuitState.HALF_OPEN, transitioned=True)

        # half_open
        if (peer.circuit_half_open_probe_count or 0) >= self.settings.circuit_half_open_probe_limit:
            return CircuitGateResult(allowed=False, state=state, reason="circuit-half-open-probe-limit")
        peer.circuit_half_open_probe_count = int(peer.circuit_half_open_probe_count or 0) + 1
        peer.updated_at = now
        return CircuitGateResult(allowed=True, state=state)

    def mark_success(self, peer: FederationTrustedPeer) -> bool:
        now = self._now()
        was_open = peer.circuit_state != CircuitState.CLOSED.value
        peer.circuit_state = CircuitState.CLOSED.value
        peer.circuit_requires_admin_reset = False
        peer.circuit_failure_count = 0
        peer.circuit_opened_at = None
        peer.circuit_next_attempt_at = None
        peer.circuit_half_open_probe_count = 0
        peer.circuit_last_failure_reason = None
        peer.updated_at = now
        return was_open

    def mark_failure(self, peer: FederationTrustedPeer, *, classification: FailureClassification) -> CircuitState:
        now = self._now()
        if classification.kind == "none" or classification.reason is None:
            return CircuitState(peer.circuit_state or "closed")

        if classification.kind == "permanent":
            peer.circuit_state = CircuitState.OPEN.value
            peer.circuit_requires_admin_reset = True
            peer.circuit_failure_count = max(int(peer.circuit_failure_count or 0), 1)
            peer.circuit_opened_at = now
            peer.circuit_next_attempt_at = None
            peer.circuit_half_open_probe_count = 0
            peer.circuit_last_failure_reason = classification.reason.value
            peer.updated_at = now
            return CircuitState.OPEN

        # transient
        failure_count = int(peer.circuit_failure_count or 0) + 1
        peer.circuit_failure_count = failure_count
        should_open = (
            peer.circuit_state == CircuitState.HALF_OPEN.value
            or failure_count >= self.settings.circuit_open_threshold
        )
        if should_open:
            exponent = max(failure_count - 1, 0)
            factor = 2 ** min(exponent, 10)
            jitter = min(1.25, max(0.75, float(self._jitter())))
            seconds = min(
                self.settings.circuit_max_open_seconds,
                int(self.settings.circuit_base_open_seconds * factor * jitter),
            )
            seconds = max(1, seconds)
            peer.circuit_state = CircuitState.OPEN.value
            peer.circuit_requires_admin_reset = False
            peer.circuit_opened_at = now
            peer.circuit_next_attempt_at = now + timedelta(seconds=seconds)
            peer.circuit_half_open_probe_count = 0
        peer.circuit_last_failure_reason = classification.reason.value
        peer.updated_at = now
        return CircuitState(peer.circuit_state or "closed")

    def reset(self, peer: FederationTrustedPeer) -> None:
        self.mark_success(peer)
