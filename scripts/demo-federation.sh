#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lfs-fed-demo.XXXXXX")"
PRESERVE="${FEDERATION_DEMO_PRESERVE_KEYS:-0}"
ADMIN_TOKEN="${FEDERATION_DEMO_ADMIN_TOKEN:-$(uv run python - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)}"
NODE_A_ID="${FEDERATION_DEMO_NODE_A_ID:-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}"
NODE_B_ID="${FEDERATION_DEMO_NODE_B_ID:-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb}"

cleanup() {
  if [[ "${PRESERVE}" != "1" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

gen_key() {
  local out_file="$1"
  uv run python - <<'PY' "$out_file"
import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
path = sys.argv[1]
key = Ed25519PrivateKey.generate()
pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
with open(path, "wb") as fh:
    fh.write(pem)
os.chmod(path, 0o600)
PY
}

json_get() {
  uv run python - <<'PY' "$1" "$2"
import json, sys
obj = json.loads(sys.argv[1])
key = sys.argv[2]
cur = obj
for part in key.split("."):
    if part.isdigit():
        cur = cur[int(part)]
    else:
        cur = cur[part]
print(cur if not isinstance(cur, (dict, list)) else json.dumps(cur))
PY
}

url_encode() {
  uv run python - <<'PY' "$1"
from urllib.parse import quote
import sys
print(quote(sys.argv[1], safe=""))
PY
}

sync_request() {
  local peer_id="$1"
  local response
  for _ in $(seq 1 30); do
    response="$(curl -sS -w '\n%{http_code}' -X POST "http://localhost:12124/api/v1/admin/federation/peers/${peer_id}/sync" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}")"
    body="$(echo "$response" | sed '$d')"
    code="$(echo "$response" | tail -n1)"
    if [[ "$code" == "200" ]]; then
      echo "$body"
      return 0
    fi
    if [[ "$code" == "409" ]]; then
      sleep 1
      continue
    fi
    echo "$body" >&2
    return 1
  done
  echo "Synchronization lock did not clear in time." >&2
  return 1
}

wait_ready() {
  local url="$1"
  local name="$2"
  for _ in $(seq 1 60); do
    body="$(curl -fsS "$url" 2>/dev/null || true)"
    if [[ -n "$body" ]]; then
      state="$(json_get "$body" "status" 2>/dev/null || true)"
      if [[ "$state" == "ready" ]]; then
        echo "${name}: ready"
        return 0
      fi
    fi
    sleep 2
  done
  echo "${name}: not ready" >&2
  return 1
}

KEY_A="${TMP_DIR}/node-a-signing-key.pem"
KEY_B="${TMP_DIR}/node-b-signing-key.pem"
gen_key "${KEY_A}"
gen_key "${KEY_B}"

export FEDERATION_DEMO_NODE_A_KEY_FILE="${KEY_A}"
export FEDERATION_DEMO_NODE_B_KEY_FILE="${KEY_B}"
export FEDERATION_DEMO_ADMIN_TOKEN="${ADMIN_TOKEN}"
export FEDERATION_DEMO_NODE_A_ID="${NODE_A_ID}"
export FEDERATION_DEMO_NODE_B_ID="${NODE_B_ID}"

cd "${ROOT_DIR}"
docker compose --profile federation-demo down --remove-orphans --volumes >/dev/null 2>&1 || true
docker compose --profile federation-demo up --build -d --force-recreate

wait_ready "http://localhost:12114/api/v1/ready" "Node A"
wait_ready "http://localhost:12124/api/v1/ready" "Node B"

JWKS_A="$(curl -fsS http://localhost:12114/.well-known/jwks.json)"
KID_A="$(json_get "${JWKS_A}" "keys.0.kid")"
X_A="$(json_get "${JWKS_A}" "keys.0.x")"
FPR_A="$(uv run python - <<'PY' "$X_A"
import base64, hashlib, sys
x = sys.argv[1]
raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
print(hashlib.sha256(raw).hexdigest())
PY
)"
echo "Node A key fingerprint: ${FPR_A}"

PEER_CREATE_PAYLOAD="$(uv run python - <<'PY' "$NODE_A_ID" "$KID_A" "$FPR_A"
import json, sys
print(json.dumps({
  "peerNodeId": sys.argv[1],
  "baseUrl": "http://node-a:12104",
  "peerName": "Demo Node A",
  "operatorName": "Demo Operator A",
  "verificationKey": {"kid": sys.argv[2], "fingerprint": sys.argv[3]},
  "allowPrivateNetwork": True,
  "allowedHostnames": ["node-a"],
}))
PY
)"

PEER_CREATED="$(curl -fsS -X POST http://localhost:12124/api/v1/admin/federation/peers \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d "${PEER_CREATE_PAYLOAD}")"
PEER_ID="$(json_get "${PEER_CREATED}" "id")"
echo "Peer enrollment on B: trusted"

BAD_CREATE_PAYLOAD="$(uv run python - <<'PY' "$NODE_A_ID"
import json
import sys
print(json.dumps({
  "peerNodeId": sys.argv[1],
  "baseUrl": "http://127.0.0.1:12104",
  "peerName": "Bad Peer",
  "operatorName": "Bad Operator",
  "verificationKey": {"kid": "dummy", "fingerprint": "00"},
  "allowPrivateNetwork": True,
}))
PY
)"
BAD_CREATE_RESPONSE="$(curl -sS -w '\n%{http_code}' -X POST http://localhost:12124/api/v1/admin/federation/peers \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d "${BAD_CREATE_PAYLOAD}")"
BAD_CREATE_CODE="$(echo "$BAD_CREATE_RESPONSE" | tail -n1)"
[[ "${BAD_CREATE_CODE}" != "200" ]]
echo "Unapproved private target rejected: yes"

PUB_PAYLOAD='{"localId":"Demo-License","version":"1","payload":{"licenseId":"Demo-License","name":"Demo License"}}'
PUBLISHED="$(curl -fsS -X POST http://localhost:12114/api/v1/admin/federation/publish \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d "${PUB_PAYLOAD}")"
CANONICAL_ID="$(json_get "${PUBLISHED}" "canonicalId")"
echo "Published on A: ${CANONICAL_ID}"
CHANGES_A="$(curl -fsS http://localhost:12114/api/v1/federation/changes?limit=1)"
POSITION_A="$(json_get "${CHANGES_A}" "events.0.payload.eventPosition")"
echo "A event position: ${POSITION_A}"

SYNC1="$(sync_request "${PEER_ID}")"
[[ "$(json_get "${SYNC1}" "status")" == "complete" ]]
echo "B signature verification: passed"
echo "B record digest verification: passed"

ENC_CANONICAL_ID="$(url_encode "${CANONICAL_ID}")"
RESOLUTION_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=${ENC_CANONICAL_ID}")"
[[ "$(json_get "${RESOLUTION_B}" "resolutionOutcome")" == "imported" ]]
[[ "$(json_get "${RESOLUTION_B}" "authorityNodeId")" == "${NODE_A_ID}" ]]
[[ "$(json_get "${RESOLUTION_B}" "sourcePeerId")" == "${PEER_ID}" ]]
[[ "$(json_get "${RESOLUTION_B}" "canonicalId")" == "${CANONICAL_ID}" ]]
echo "B resolution outcome: imported"
echo "B resolution authority: ${NODE_A_ID}"
echo "B source peer: ${PEER_ID}"

PROVENANCE_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/provenance?identifier=${ENC_CANONICAL_ID}")"
[[ "$(json_get "${PROVENANCE_B}" "events.0.sourcePeerId")" == "${PEER_ID}" ]]
[[ "$(json_get "${PROVENANCE_B}" "events.0.sourcePeerNodeId")" == "${NODE_A_ID}" ]]
[[ "$(json_get "${PROVENANCE_B}" "events.0.eventPosition")" == "${POSITION_A}" ]]
echo "B provenance history: signed inbound event recorded"

CATALOG_B="$(curl -fsS http://localhost:12124/api/v1/federation/catalog)"
CHANGES_B="$(curl -fsS http://localhost:12124/api/v1/federation/changes?limit=10)"
[[ "${CATALOG_B}" != *"${CANONICAL_ID}"* ]]
[[ "${CHANGES_B}" != *"${CANONICAL_ID}"* ]]
echo "B outbound catalog/changes exclude imported record: yes"

IMPORTS="$(curl -fsS "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/imports" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")"
COUNT_IMPORTS="$(json_get "${IMPORTS}" "total")"
[[ "${COUNT_IMPORTS}" -ge 1 ]]
echo "B imported records: ${COUNT_IMPORTS}"
AUTHORITY="$(json_get "${IMPORTS}" "items.0.authorityNodeId")"
IS_AUTH="$(json_get "${IMPORTS}" "items.0.isAuthoritative")"
[[ "${AUTHORITY}" == "${NODE_A_ID}" ]]
[[ "${IS_AUTH}" == "False" || "${IS_AUTH}" == "false" ]]
echo "B authority: ${AUTHORITY}"
echo "B is authoritative: false"
echo "B provenance source: ${AUTHORITY}"

SYNC2="$(sync_request "${PEER_ID}")"
IMPORTED2="$(json_get "${SYNC2}" "importedRecords")"
[[ "${IMPORTED2}" == "0" ]]
echo "Second synchronization imported: 0"

CURSOR_BEFORE="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ -n "${CURSOR_BEFORE}" ]]
echo "B resume cursor persisted: yes"
TAMPER_EVENT_ID="$(uuidgen)"
TAMPER_RECORD_ID="$(docker compose exec -T node-a-db psql -U postgres -d lfs_a -tAc "SELECT id FROM federation_records ORDER BY created_at DESC LIMIT 1" | tr -d '[:space:]')"
docker compose exec -T node-a-db psql -U postgres -d lfs_a -c "INSERT INTO federation_change_events (id, event_sequence, event_type, authority_node_id, record_id, operation, generated_at, payload_schema_version, signed_payload, signed_payload_digest_sha256, signature_base64url, signature_kid, signature_alg, provenance_type, event_payload, event_digest_sha256, occurred_at, created_at) VALUES ('${TAMPER_EVENT_ID}', ${POSITION_A} + 1, 'record.changed', '${NODE_A_ID}', '${TAMPER_RECORD_ID}', 'upsert', NOW(), '1', '{\"tampered\":true}'::jsonb, 'bad', 'tampered', 'node-a-k1', 'EdDSA', 'publication', '{}'::jsonb, 'bad', NOW(), NOW());" >/dev/null
TAMPER_SYNC="$(sync_request "${PEER_ID}")"
TAMPER_STATUS="$(json_get "${TAMPER_SYNC}" "status")"
TAMPER_IMPORTED="$(json_get "${TAMPER_SYNC}" "importedRecords")"
[[ "${TAMPER_STATUS}" != "complete" ]]
[[ "${TAMPER_IMPORTED}" == "0" ]]
CURSOR_AFTER="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ "${CURSOR_AFTER}" == "${CURSOR_BEFORE}" ]]
echo "Tampered event rejected: yes"
echo "Cursor unchanged after tampering: yes"

docker compose stop node-a >/dev/null
SYNC_OFFLINE="$(sync_request "${PEER_ID}")"
OFFLINE_STATUS="$(json_get "${SYNC_OFFLINE}" "status")"
[[ "${OFFLINE_STATUS}" == "partial" || "${OFFLINE_STATUS}" == "failed" ]]
RESOLUTION_OFFLINE="$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=${ENC_CANONICAL_ID}")"
[[ "$(json_get "${RESOLUTION_OFFLINE}" "resolutionOutcome")" == "imported" ]]
[[ "$(json_get "${RESOLUTION_OFFLINE}" "freshnessState")" == "stale" ]]
[[ "$(json_get "${RESOLUTION_OFFLINE}" "sourceAvailability")" == "offline" ]]
echo "Offline record retained: yes"
echo "Offline freshness state: stale"

echo "Federation demo: PASSED"
