#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${ROOT_DIR}/.tmp"
mkdir -p "${TMP_ROOT}"
TMP_DIR="$(mktemp -d "${TMP_ROOT}/lfs-fed-demo.XXXXXX")"
PRESERVE="${FEDERATION_DEMO_PRESERVE_KEYS:-0}"
RUN_ID="$(uv run python - <<'PY'
import uuid
print(uuid.uuid4().hex[:10])
PY
)"
ADMIN_TOKEN="${FEDERATION_DEMO_ADMIN_TOKEN:-$(uv run python - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)}"
CURSOR_SECRET="${FEDERATION_DEMO_CURSOR_SECRET:-$(uv run python - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)}"
NODE_A_ID="${FEDERATION_DEMO_NODE_A_ID:-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}"
NODE_B_ID="${FEDERATION_DEMO_NODE_B_ID:-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb}"
NODE_A_K1="${FEDERATION_DEMO_NODE_A_K1:-node-a-k1}"
NODE_A_K2="${FEDERATION_DEMO_NODE_A_K2:-node-a-k2}"
NODE_B_K1="${FEDERATION_DEMO_NODE_B_K1:-node-b-k1}"
NODE_A_WORKER_ID="${FEDERATION_DEMO_NODE_A_WORKER_ID:-aaaaaaaa-aaaa-4aaa-8aaa-0000000000a1}"
NODE_B_WORKER_ID="${FEDERATION_DEMO_NODE_B_WORKER_ID:-bbbbbbbb-bbbb-4bbb-8bbb-0000000000b1}"
CURATOR_TOKEN="${FEDERATION_DEMO_CURATOR_TOKEN:-}"
TRANSCRIPT="${TMP_DIR}/demo-transcript.log"

cleanup() {
  if [[ "${PRESERVE}" != "1" ]]; then
    rm -rf "${TMP_DIR}"
  else
    echo "Preserved demo artifacts at ${TMP_DIR}"
  fi
}
trap cleanup EXIT

append_transcript() {
  local label="$1"
  local body="$2"
  {
    echo "### ${label}"
    echo "${body}"
  } >>"${TRANSCRIPT}"
}

json_get() {
  uv run python - <<'PY' "$1" "$2"
import json
import sys
obj = json.loads(sys.argv[1])
cur = obj
for part in sys.argv[2].split("."):
    if part.isdigit():
        cur = cur[int(part)]
    else:
        cur = cur[part]
if isinstance(cur, (dict, list)):
    print(json.dumps(cur, separators=(",", ":")))
else:
    print(cur)
PY
}

json_len() {
  uv run python - <<'PY' "$1" "$2"
import json
import sys
obj = json.loads(sys.argv[1])
cur = obj
for part in sys.argv[2].split("."):
    if part.isdigit():
        cur = cur[int(part)]
    else:
        cur = cur[part]
print(len(cur))
PY
}

url_encode() {
  uv run python - <<'PY' "$1"
from urllib.parse import quote
import sys
print(quote(sys.argv[1], safe=""))
PY
}

encode_record_id() {
  uv run python - <<'PY' "$1"
import base64
import sys
print(base64.urlsafe_b64encode(sys.argv[1].encode("utf-8")).decode("ascii").rstrip("="))
PY
}

http_request() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local auth="${4:-1}"
  local -a args
  args=(-sS -w $'\n%{http_code}' -X "${method}" "${url}")
  if [[ "${auth}" == "1" ]]; then
    args+=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
  fi
  if [[ -n "${data}" ]]; then
    args+=(-H "Content-Type: application/json" -d "${data}")
  fi
  curl "${args[@]}"
}

expect_code() {
  local response="$1"
  local expected="$2"
  local body code
  body="$(echo "${response}" | sed '$d')"
  code="$(echo "${response}" | tail -n1)"
  if [[ "${code}" != "${expected}" ]]; then
    echo "Expected HTTP ${expected}, got ${code}" >&2
    echo "${body}" >&2
    exit 1
  fi
  echo "${body}"
}

wait_ready() {
  local url="$1"
  local name="$2"
  for _ in $(seq 1 120); do
    body="$(curl -fsS "${url}" 2>/dev/null || true)"
    if [[ -n "${body}" ]]; then
      state="$(json_get "${body}" "status" 2>/dev/null || true)"
      if [[ "${state}" == "ready" ]]; then
        echo "${name}: ready"
        return 0
      fi
    fi
    sleep 1
  done
  echo "${name}: not ready" >&2
  return 1
}

sync_request() {
  local peer_id="$1"
  local response body code
  for _ in $(seq 1 60); do
    response="$(http_request "POST" "http://localhost:12124/api/v1/admin/federation/peers/${peer_id}/sync")"
    body="$(echo "${response}" | sed '$d')"
    code="$(echo "${response}" | tail -n1)"
    if [[ "${code}" == "200" ]]; then
      echo "${body}"
      return 0
    fi
    if [[ "${code}" == "409" ]]; then
      sleep 1
      continue
    fi
    echo "${body}" >&2
    return 1
  done
  echo "Synchronization lease did not clear in time." >&2
  return 1
}

gen_private_key() {
  local out_file="$1"
  uv run python - <<'PY' "${out_file}"
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

fetch_jwks_etag() {
  curl -fsS -D - -o /dev/null "$1" | tr -d '\r' | awk 'BEGIN{IGNORECASE=1} /^etag: /{print substr($0,7)}' | tail -n1
}

NODE_A_KEY_DIR="${TMP_DIR}/node-a-keys"
NODE_B_KEY_DIR="${TMP_DIR}/node-b-keys"
mkdir -p "${NODE_A_KEY_DIR}" "${NODE_B_KEY_DIR}"
chmod 700 "${NODE_A_KEY_DIR}" "${NODE_B_KEY_DIR}"
gen_private_key "${NODE_A_KEY_DIR}/${NODE_A_K1}.pem"
gen_private_key "${NODE_A_KEY_DIR}/${NODE_A_K2}.pem"
gen_private_key "${NODE_B_KEY_DIR}/${NODE_B_K1}.pem"

export FEDERATION_DEMO_NODE_A_KEY_DIR="${NODE_A_KEY_DIR}"
export FEDERATION_DEMO_NODE_B_KEY_DIR="${NODE_B_KEY_DIR}"
export FEDERATION_DEMO_NODE_A_KID="${NODE_A_K1}"
export FEDERATION_DEMO_NODE_B_KID="${NODE_B_K1}"
export FEDERATION_DEMO_ADMIN_TOKEN="${ADMIN_TOKEN}"
export FEDERATION_DEMO_CURSOR_SECRET="${CURSOR_SECRET}"
export FEDERATION_DEMO_NODE_A_ID="${NODE_A_ID}"
export FEDERATION_DEMO_NODE_B_ID="${NODE_B_ID}"
export FEDERATION_DEMO_NODE_A_WORKER_ID="${NODE_A_WORKER_ID}"
export FEDERATION_DEMO_NODE_B_WORKER_ID="${NODE_B_WORKER_ID}"

cd "${ROOT_DIR}"
docker compose --profile federation-demo down --remove-orphans --volumes >/dev/null 2>&1 || true
docker compose --profile federation-demo up --build -d --force-recreate

wait_ready "http://localhost:12114/api/v1/ready" "Node A"
wait_ready "http://localhost:12124/api/v1/ready" "Node B"

DISCOVERY_A_INITIAL="$(curl -fsS http://localhost:12114/.well-known/lfs)"
JWKS_A_INITIAL="$(curl -fsS http://localhost:12114/.well-known/jwks.json)"
JWKS_ETAG_INITIAL="$(fetch_jwks_etag "http://localhost:12114/.well-known/jwks.json")"
append_transcript "node-a-discovery-initial" "${DISCOVERY_A_INITIAL}"
append_transcript "node-a-jwks-initial" "${JWKS_A_INITIAL}"
[[ "$(json_get "${DISCOVERY_A_INITIAL}" "currentSigningKid")" == "${NODE_A_K1}" ]]
[[ "$(json_get "${JWKS_A_INITIAL}" "keys.0.kid")" == "${NODE_A_K1}" ]]

X_A1="$(json_get "${JWKS_A_INITIAL}" "keys.0.x")"
FPR_A1_HEX="$(uv run python - <<'PY' "${X_A1}"
import base64
import hashlib
import sys
x = sys.argv[1]
raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
print(hashlib.sha256(raw).hexdigest())
PY
)"

PEER_CREATE_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_ID}" "${NODE_A_K1}" "${FPR_A1_HEX}"
import json
import sys
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
PEER_CREATED="$(expect_code "$(http_request POST "http://localhost:12124/api/v1/admin/federation/peers" "${PEER_CREATE_PAYLOAD}")" "200")"
append_transcript "peer-created" "${PEER_CREATED}"
PEER_ID="$(json_get "${PEER_CREATED}" "id")"
echo "Peer enrollment on B: trusted (${PEER_ID})"

BAD_CREATE_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_ID}"
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
BAD_CREATE_RESPONSE="$(http_request POST "http://localhost:12124/api/v1/admin/federation/peers" "${BAD_CREATE_PAYLOAD}")"
BAD_CREATE_BODY="$(echo "${BAD_CREATE_RESPONSE}" | sed '$d')"
BAD_CREATE_CODE="$(echo "${BAD_CREATE_RESPONSE}" | tail -n1)"
append_transcript "bad-peer-create" "${BAD_CREATE_BODY}"
[[ "${BAD_CREATE_CODE}" != "200" ]]
echo "Unapproved private target rejected: yes"

LOCAL_CUSTOM_REQUESTED_ID="Demo-Local-${RUN_ID}"
LOCAL_CUSTOM_PAYLOAD="$(uv run python - <<'PY' "${LOCAL_CUSTOM_REQUESTED_ID}"
import json
import sys
print(json.dumps({
    "requestedLicenseId": sys.argv[1],
    "version": "1.0",
    "name": "Demo Local Custom License",
    "summary": "Demo local custom licence.",
    "description": "Local-only demonstration record.",
    "licenseText": "Demo local licence text.",
    "scope": "local",
    "aliases": [f"{sys.argv[1]}-alias"],
}))
PY
)"
LOCAL_CUSTOM_CREATED="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/licenses" "${LOCAL_CUSTOM_PAYLOAD}")" "201")"
append_transcript "custom-local-created" "${LOCAL_CUSTOM_CREATED}"
LOCAL_CUSTOM_ID="$(json_get "${LOCAL_CUSTOM_CREATED}" "id")"
LOCAL_CUSTOM_CANONICAL_ID="$(json_get "${LOCAL_CUSTOM_CREATED}" "canonicalId")"
LOCAL_CUSTOM_STATUS="$(expect_code "$(http_request GET "http://localhost:12114/api/v1/admin/licenses/${LOCAL_CUSTOM_ID}/federation")" "200")"
append_transcript "custom-local-status-node-a" "${LOCAL_CUSTOM_STATUS}"
[[ "$(json_get "${LOCAL_CUSTOM_STATUS}" "customLicenceId")" == "${LOCAL_CUSTOM_ID}" ]]
[[ "$(json_get "${LOCAL_CUSTOM_STATUS}" "federationStatus")" == "not_published" ]]
CATALOG_A_AFTER_LOCAL="$(curl -fsS "http://localhost:12114/api/v1/federation/catalog?limit=200")"
CHANGES_A_AFTER_LOCAL="$(curl -fsS "http://localhost:12114/api/v1/federation/changes?limit=200")"
append_transcript "catalog-a-after-local" "${CATALOG_A_AFTER_LOCAL}"
append_transcript "changes-a-after-local" "${CHANGES_A_AFTER_LOCAL}"
[[ "${CATALOG_A_AFTER_LOCAL}" != *"${LOCAL_CUSTOM_CANONICAL_ID}"* ]]
[[ "${CHANGES_A_AFTER_LOCAL}" != *"${LOCAL_CUSTOM_CANONICAL_ID}"* ]]
echo "Local-scope custom licence is stored locally and absent from outbound federation feed"

FED_CUSTOM_REQUESTED_ID="Demo-Federated-${RUN_ID}"
FED_CUSTOM_PAYLOAD="$(uv run python - <<'PY' "${FED_CUSTOM_REQUESTED_ID}"
import json
import sys
print(json.dumps({
    "requestedLicenseId": sys.argv[1],
    "version": "1.0",
    "name": "Demo Federated Custom License",
    "summary": "Demo federated custom licence.",
    "description": "Federated demonstration record.",
    "licenseText": "Demo federated licence text.",
    "scope": "federated",
    "aliases": [f"{sys.argv[1]}-alias"],
}))
PY
)"
FED_CUSTOM_CREATED="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/licenses" "${FED_CUSTOM_PAYLOAD}")" "201")"
append_transcript "custom-federated-created" "${FED_CUSTOM_CREATED}"
FED_CUSTOM_ID="$(json_get "${FED_CUSTOM_CREATED}" "id")"
[[ "$(json_get "${FED_CUSTOM_CREATED}" "federationStatus")" == "pending" ]]

FED_CUSTOM_STATUS=""
for _ in $(seq 1 90); do
  FED_CUSTOM_STATUS="$(expect_code "$(http_request GET "http://localhost:12114/api/v1/admin/licenses/${FED_CUSTOM_ID}/federation")" "200")"
  if [[ "$(json_get "${FED_CUSTOM_STATUS}" "federationStatus")" == "published" ]]; then
    break
  fi
  sleep 1
done
append_transcript "custom-federated-status" "${FED_CUSTOM_STATUS}"
[[ "$(json_get "${FED_CUSTOM_STATUS}" "federationStatus")" == "published" ]]

CHANGES_A_AFTER_FED_CUSTOM="$(curl -fsS "http://localhost:12114/api/v1/federation/changes?limit=200")"
append_transcript "changes-a-after-federated-custom" "${CHANGES_A_AFTER_FED_CUSTOM}"
FED_CUSTOM_CANONICAL_ID="$(uv run python - <<'PY' "${CHANGES_A_AFTER_FED_CUSTOM}" "${FED_CUSTOM_ID}"
import json
import sys
events = json.loads(sys.argv[1]).get("events", [])
target = sys.argv[2]
for evt in events:
    payload = evt.get("payload", {})
    record = payload.get("record", {})
    business = record.get("payload", {})
    if business.get("schema") == "lfs.custom-licence.federation.v1" and business.get("customLicenceId") == target:
        print(record.get("canonicalId"))
        raise SystemExit(0)
raise SystemExit(1)
PY
)"
FED_CUSTOM_ENCODED="$(encode_record_id "${FED_CUSTOM_CANONICAL_ID}")"
FED_CUSTOM_RECORD_A="$(curl -fsS "http://localhost:12114/api/v1/federation/records/${FED_CUSTOM_ENCODED}")"
append_transcript "custom-federated-record-node-a" "${FED_CUSTOM_RECORD_A}"
[[ "$(json_get "${FED_CUSTOM_RECORD_A}" "record.payload.schema")" == "lfs.custom-licence.federation.v1" ]]
echo "Federated custom licence published on Node A authoritative feed"

SYNC_CUSTOM_ON_B="$(sync_request "${PEER_ID}")"
append_transcript "sync-federated-custom" "${SYNC_CUSTOM_ON_B}"
[[ "$(json_get "${SYNC_CUSTOM_ON_B}" "status")" == "complete" ]]
FED_CUSTOM_RESOLUTION_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=$(url_encode "${FED_CUSTOM_CANONICAL_ID}")")"
FED_CUSTOM_PROVENANCE_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/provenance?identifier=$(url_encode "${FED_CUSTOM_CANONICAL_ID}")")"
append_transcript "custom-federated-resolution-node-b" "${FED_CUSTOM_RESOLUTION_B}"
append_transcript "custom-federated-provenance-node-b" "${FED_CUSTOM_PROVENANCE_B}"
[[ "$(json_get "${FED_CUSTOM_RESOLUTION_B}" "resolutionOutcome")" == "imported" ]]
[[ "$(json_get "${FED_CUSTOM_RESOLUTION_B}" "authorityNodeId")" == "${NODE_A_ID}" ]]
[[ "$(json_get "${FED_CUSTOM_PROVENANCE_B}" "events.0.sourcePeerId")" == "${PEER_ID}" ]]
CATALOG_B_AFTER_FED_CUSTOM="$(curl -fsS "http://localhost:12124/api/v1/federation/catalog?limit=200")"
CHANGES_B_AFTER_FED_CUSTOM="$(curl -fsS "http://localhost:12124/api/v1/federation/changes?limit=200")"
append_transcript "catalog-b-after-federated-custom" "${CATALOG_B_AFTER_FED_CUSTOM}"
append_transcript "changes-b-after-federated-custom" "${CHANGES_B_AFTER_FED_CUSTOM}"
[[ "${CATALOG_B_AFTER_FED_CUSTOM}" != *"${FED_CUSTOM_CANONICAL_ID}"* ]]
[[ "${CHANGES_B_AFTER_FED_CUSTOM}" != *"${FED_CUSTOM_CANONICAL_ID}"* ]]
SYNC_CUSTOM_REPEAT="$(sync_request "${PEER_ID}")"
append_transcript "sync-federated-custom-repeat" "${SYNC_CUSTOM_REPEAT}"
[[ "$(json_get "${SYNC_CUSTOM_REPEAT}" "importedRecords")" == "0" ]]
echo "Federated custom licence import on B is non-authoritative and idempotent"

SPDX_MINIMAL_PAYLOAD="$(uv run python - <<'PY' "${RUN_ID}"
import json
import sys
print(json.dumps({
    "name": f"Demo SPDX {sys.argv[1]}",
    "namespace": f"https://example.org/demo/{sys.argv[1]}",
}))
PY
)"
SPDX_MINIMAL_RESULT="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/licenses/spdx3/minimal" "${SPDX_MINIMAL_PAYLOAD}")" "200")"
append_transcript "spdx3-minimal-demo" "${SPDX_MINIMAL_RESULT}"
[[ "$(json_get "${SPDX_MINIMAL_RESULT}" "@context")" == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld" ]]
echo "SPDX minimal validation path: passed"

STAGE_EXTRA_FIELD_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_K2}"
import json
import sys
print(json.dumps({
    "kid": sys.argv[1],
    "expectedState": "staged",
    "reason": "schema-extra-field-check",
    "privateKeyPath": "/tmp/forbidden.pem",
}))
PY
)"
STAGE_EXTRA_FIELD_RESP="$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/stage" "${STAGE_EXTRA_FIELD_PAYLOAD}")"
STAGE_EXTRA_FIELD_BODY="$(echo "${STAGE_EXTRA_FIELD_RESP}" | sed '$d')"
STAGE_EXTRA_FIELD_CODE="$(echo "${STAGE_EXTRA_FIELD_RESP}" | tail -n1)"
append_transcript "stage-extra-field" "${STAGE_EXTRA_FIELD_BODY}"
[[ "${STAGE_EXTRA_FIELD_CODE}" == "422" ]]
echo "Private-key/path stage fields rejected: yes"

ACT_WARN_FALSE_PAYLOAD='{"expectedState":"staged","reason":"demo warning ack check","warningAck":false}'
ACT_WARN_MISSING_PAYLOAD='{"expectedState":"staged","reason":"demo warning ack check"}'
ACT_WARN_FALSE_BODY="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/${NODE_A_K2}/activate" "${ACT_WARN_FALSE_PAYLOAD}")" "400")"
ACT_WARN_MISSING_BODY="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/${NODE_A_K2}/activate" "${ACT_WARN_MISSING_PAYLOAD}")" "400")"
append_transcript "activate-warning-false" "${ACT_WARN_FALSE_BODY}"
append_transcript "activate-warning-missing" "${ACT_WARN_MISSING_BODY}"

EMERGENCY_WARN_FALSE_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_K2}"
import json
import sys
print(json.dumps({
    "expectedState": "active",
    "successorKid": sys.argv[1],
    "successorExpectedState": "staged",
    "reason": "demo warning ack check",
    "warningAck": False,
}))
PY
)"
EMERGENCY_WARN_FALSE_BODY="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/${NODE_A_K1}/revoke-emergency" "${EMERGENCY_WARN_FALSE_PAYLOAD}")" "400")"
append_transcript "emergency-warning-false" "${EMERGENCY_WARN_FALSE_BODY}"

UNAUTH_WARN_FALSE_RESP="$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/${NODE_A_K2}/activate" "${ACT_WARN_FALSE_PAYLOAD}" "0")"
UNAUTH_WARN_FALSE_BODY="$(echo "${UNAUTH_WARN_FALSE_RESP}" | sed '$d')"
UNAUTH_WARN_FALSE_CODE="$(echo "${UNAUTH_WARN_FALSE_RESP}" | tail -n1)"
append_transcript "unauth-activate-warning-false" "${UNAUTH_WARN_FALSE_BODY}"
[[ "${UNAUTH_WARN_FALSE_CODE}" == "401" ]]
echo "warningAck enforcement and auth ordering checks: passed"

if [[ -n "${CURATOR_TOKEN}" ]]; then
  CURATOR_RESP="$(curl -sS -w $'\n%{http_code}' -X GET "http://localhost:12114/api/v1/admin/federation/signing-keys" -H "Authorization: Bearer ${CURATOR_TOKEN}")"
  CURATOR_BODY="$(echo "${CURATOR_RESP}" | sed '$d')"
  CURATOR_CODE="$(echo "${CURATOR_RESP}" | tail -n1)"
  append_transcript "curator-admin-attempt" "${CURATOR_BODY}"
  [[ "${CURATOR_CODE}" == "403" ]]
  echo "Curator admin-path rejection: 403"
fi

PUB_R1_PAYLOAD="$(uv run python - <<'PY' "${RUN_ID}"
import json
import sys
print(json.dumps({
    "localId": f"Demo-License-{sys.argv[1]}-R1",
    "version": "1",
    "payload": {"licenseId": f"Demo-License-{sys.argv[1]}-R1", "name": "Demo License R1"},
}))
PY
)"
PUBLISHED_R1="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/publish" "${PUB_R1_PAYLOAD}")" "200")"
append_transcript "published-r1" "${PUBLISHED_R1}"
CANONICAL_R1="$(json_get "${PUBLISHED_R1}" "canonicalId")"

CHANGES_A_R1="$(curl -fsS "http://localhost:12114/api/v1/federation/changes?limit=200")"
append_transcript "changes-a-r1" "${CHANGES_A_R1}"
R1_EVENT_FIELDS="$(uv run python - <<'PY' "${CHANGES_A_R1}" "${CANONICAL_R1}"
import json
import sys
events = json.loads(sys.argv[1]).get("events", [])
target = sys.argv[2]
for evt in events:
    payload = evt.get("payload", {})
    record = payload.get("record", {})
    if record.get("canonicalId") == target:
        print(json.dumps({
            "digest": evt["signed"]["digestSha256"],
            "kid": evt["signed"]["signature"]["kid"],
            "sig": evt["signed"]["signature"]["value"],
            "position": payload["eventPosition"],
        }))
        raise SystemExit(0)
raise SystemExit(1)
PY
)"
R1_EVENT_DIGEST="$(json_get "${R1_EVENT_FIELDS}" "digest")"
R1_SIG_KID="$(json_get "${R1_EVENT_FIELDS}" "kid")"
R1_SIG_VALUE="$(json_get "${R1_EVENT_FIELDS}" "sig")"
R1_EVENT_POSITION="$(json_get "${R1_EVENT_FIELDS}" "position")"
[[ "${R1_SIG_KID}" == "${NODE_A_K1}" ]]
echo "R1 published on A: ${CANONICAL_R1}"

SYNC_R1="$(sync_request "${PEER_ID}")"
append_transcript "sync-r1" "${SYNC_R1}"
[[ "$(json_get "${SYNC_R1}" "status")" == "complete" ]]
echo "R1 synchronized to B: complete"

ENC_CANONICAL_R1="$(url_encode "${CANONICAL_R1}")"
RESOLUTION_R1_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=${ENC_CANONICAL_R1}")"
append_transcript "resolution-r1-b" "${RESOLUTION_R1_B}"
[[ "$(json_get "${RESOLUTION_R1_B}" "resolutionOutcome")" == "imported" ]]
[[ "$(json_get "${RESOLUTION_R1_B}" "authorityNodeId")" == "${NODE_A_ID}" ]]
[[ "$(json_get "${RESOLUTION_R1_B}" "sourcePeerId")" == "${PEER_ID}" ]]
echo "B resolution outcome for R1: imported"

PROVENANCE_R1_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/provenance?identifier=${ENC_CANONICAL_R1}")"
append_transcript "provenance-r1-b" "${PROVENANCE_R1_B}"
[[ "$(json_get "${PROVENANCE_R1_B}" "events.0.sourcePeerId")" == "${PEER_ID}" ]]
[[ "$(json_get "${PROVENANCE_R1_B}" "events.0.sourcePeerNodeId")" == "${NODE_A_ID}" ]]
[[ "$(json_get "${PROVENANCE_R1_B}" "events.0.eventPosition")" == "${R1_EVENT_POSITION}" ]]

IMPORTS_B_R1="$(expect_code "$(http_request GET "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/imports")" "200")"
append_transcript "imports-r1-b" "${IMPORTS_B_R1}"
[[ "$(json_get "${IMPORTS_B_R1}" "items.0.sourceSignatureKid")" == "${NODE_A_K1}" ]]

CURSOR_R1="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ -n "${CURSOR_R1}" ]]
echo "B cursor after R1: ${CURSOR_R1}"

SYNC_REPEAT="$(sync_request "${PEER_ID}")"
append_transcript "sync-repeat-r1" "${SYNC_REPEAT}"
[[ "$(json_get "${SYNC_REPEAT}" "importedRecords")" == "0" ]]
echo "Repeated synchronization idempotence: passed"

CATALOG_B="$(curl -fsS http://localhost:12124/api/v1/federation/catalog)"
CHANGES_B="$(curl -fsS http://localhost:12124/api/v1/federation/changes?limit=20)"
append_transcript "catalog-b" "${CATALOG_B}"
append_transcript "changes-b" "${CHANGES_B}"
[[ "${CATALOG_B}" != *"${CANONICAL_R1}"* ]]
[[ "${CHANGES_B}" != *"${CANONICAL_R1}"* ]]
echo "B outbound catalog/changes exclude imported records: yes"

STAGE_A2_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_K2}"
import json
import sys
print(json.dumps({"kid": sys.argv[1], "expectedState": "staged", "reason": "demo stage A2"}))
PY
)"
STAGE_A2_RESULT="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/stage" "${STAGE_A2_PAYLOAD}")" "200")"
append_transcript "stage-a2" "${STAGE_A2_RESULT}"

KEYS_AFTER_STAGE="$(expect_code "$(http_request GET "http://localhost:12114/api/v1/admin/federation/signing-keys")" "200")"
append_transcript "keys-after-stage" "${KEYS_AFTER_STAGE}"
uv run python - <<'PY' "${KEYS_AFTER_STAGE}" "${NODE_A_K2}"
import json
import sys
items = json.loads(sys.argv[1])["items"]
k2 = [i for i in items if i["kid"] == sys.argv[2]]
assert len(k2) == 1
assert k2[0]["status"] == "staged"
assert not k2[0]["isActive"]
PY

DISCOVERY_A_STAGE="$(curl -fsS http://localhost:12114/.well-known/lfs)"
JWKS_A_STAGE="$(curl -fsS http://localhost:12114/.well-known/jwks.json)"
JWKS_ETAG_STAGE="$(fetch_jwks_etag "http://localhost:12114/.well-known/jwks.json")"
append_transcript "node-a-discovery-stage" "${DISCOVERY_A_STAGE}"
append_transcript "node-a-jwks-stage" "${JWKS_A_STAGE}"
[[ "$(json_get "${DISCOVERY_A_STAGE}" "currentSigningKid")" == "${NODE_A_K1}" ]]
[[ "$(json_len "${JWKS_A_STAGE}" "keys")" == "2" ]]
[[ "${JWKS_ETAG_STAGE}" != "${JWKS_ETAG_INITIAL}" ]]

PUB_STAGE_PAYLOAD="$(uv run python - <<'PY' "${RUN_ID}"
import json
import sys
print(json.dumps({
    "localId": f"Demo-License-{sys.argv[1]}-stage-check",
    "version": "1",
    "payload": {"licenseId": f"Demo-License-{sys.argv[1]}-stage-check", "name": "Stage check"},
}))
PY
)"
PUB_STAGE_RESULT="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/publish" "${PUB_STAGE_PAYLOAD}")" "200")"
CANONICAL_STAGE="$(json_get "${PUB_STAGE_RESULT}" "canonicalId")"
ENC_CANONICAL_STAGE="$(encode_record_id "${CANONICAL_STAGE}")"
RECORD_STAGE="$(curl -fsS "http://localhost:12114/api/v1/federation/records/${ENC_CANONICAL_STAGE}")"
append_transcript "record-after-stage-publish" "${RECORD_STAGE}"
[[ "$(json_get "${RECORD_STAGE}" "signed.signature.kid")" == "${NODE_A_K1}" ]]
echo "Outbound signatures remain on A1 while A2 staged: yes"

INSPECT_A2_B="$(expect_code "$(http_request POST "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/keys/inspect" '{"reason":"demo inspect A2"}')" "200")"
append_transcript "inspect-a2-on-b" "${INSPECT_A2_B}"
NEW_COUNT="$(json_len "${INSPECT_A2_B}" "new")"
[[ "${NEW_COUNT}" == "1" ]]
INSPECTED_NEW_KID="$(json_get "${INSPECT_A2_B}" "new.0.kid")"
INSPECTED_NEW_FPR="$(json_get "${INSPECT_A2_B}" "new.0.publicFingerprint")"
[[ "${INSPECTED_NEW_KID}" == "${NODE_A_K2}" ]]
echo "B inspection sees A2 exactly once: yes"

KEYS_B_BEFORE_APPROVAL="$(expect_code "$(http_request GET "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/keys")" "200")"
append_transcript "keys-b-before-approval" "${KEYS_B_BEFORE_APPROVAL}"
uv run python - <<'PY' "${KEYS_B_BEFORE_APPROVAL}" "${NODE_A_K2}"
import json
import sys
items = json.loads(sys.argv[1])["items"]
assert len([i for i in items if i["kid"] == sys.argv[2] and i["status"] == "active"]) == 0
PY

ACTIVATE_AT="$(docker compose exec -T node-a-db psql -U postgres -d lfs_a -tAc "SELECT to_char((NOW() + interval '4 seconds') AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')" | tr -d '[:space:]')"
SCHEDULE_A2_PAYLOAD="$(uv run python - <<'PY' "${ACTIVATE_AT}"
import json
import sys
print(json.dumps({
    "activateAt": sys.argv[1],
    "expectedState": "staged",
    "reason": "demo schedule A2 activation"
}))
PY
)"
SCHEDULE_A2_RESULT="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/${NODE_A_K2}/schedule-activation" "${SCHEDULE_A2_PAYLOAD}")" "200")"
append_transcript "schedule-a2" "${SCHEDULE_A2_RESULT}"

ACTIVATED_JSON=""
for _ in $(seq 1 90); do
  ACTIVATED_JSON="$(expect_code "$(http_request GET "http://localhost:12114/api/v1/admin/federation/signing-keys")" "200")"
  if [[ "$(uv run python - <<'PY' "${ACTIVATED_JSON}" "${NODE_A_K2}" "${NODE_A_K1}"
import json
import sys
items = json.loads(sys.argv[1])["items"]
state = {i["kid"]: i for i in items}
print(
    "yes"
    if state.get(sys.argv[2], {}).get("status") == "active"
    and state.get(sys.argv[2], {}).get("isActive") is True
    and state.get(sys.argv[3], {}).get("status") == "retired"
    else "no"
)
PY
)" == "yes" ]]; then
    break
  fi
  sleep 1
done
append_transcript "keys-after-activation-poll" "${ACTIVATED_JSON}"
uv run python - <<'PY' "${ACTIVATED_JSON}" "${NODE_A_K2}" "${NODE_A_K1}"
import json
import sys
items = json.loads(sys.argv[1])["items"]
state = {i["kid"]: i for i in items}
assert state[sys.argv[2]]["status"] == "active"
assert state[sys.argv[2]]["isActive"] is True
assert state[sys.argv[3]]["status"] == "retired"
active_count = len([i for i in items if i["isActive"]])
assert active_count == 1
assert state[sys.argv[3]]["rotatedToKid"] == sys.argv[2]
assert state[sys.argv[2]]["rotationScheduledAt"] is None
PY

DISCOVERY_A_ACTIVATED="$(curl -fsS http://localhost:12114/.well-known/lfs)"
JWKS_A_ACTIVATED="$(curl -fsS http://localhost:12114/.well-known/jwks.json)"
JWKS_ETAG_ACTIVATED="$(fetch_jwks_etag "http://localhost:12114/.well-known/jwks.json")"
append_transcript "node-a-discovery-activated" "${DISCOVERY_A_ACTIVATED}"
append_transcript "node-a-jwks-activated" "${JWKS_A_ACTIVATED}"
[[ "$(json_get "${DISCOVERY_A_ACTIVATED}" "currentSigningKid")" == "${NODE_A_K2}" ]]
[[ "${JWKS_ETAG_ACTIVATED}" != "${JWKS_ETAG_STAGE}" ]]
uv run python - <<'PY' "${JWKS_A_ACTIVATED}" "${NODE_A_K2}" "${NODE_A_K1}"
import json
import sys
keys = json.loads(sys.argv[1])["keys"]
kids = {k["kid"] for k in keys}
assert sys.argv[2] in kids
assert sys.argv[3] in kids
PY

ACTIVATION_AUDIT_COUNT="$(docker compose exec -T node-a-db psql -U postgres -d lfs_a -tAc "SELECT count(*) FROM federation_operational_audit WHERE action='local_key.activate' AND target_id='${NODE_A_K2}'" | tr -d '[:space:]')"
[[ "${ACTIVATION_AUDIT_COUNT}" == "1" ]]

STATUS_A="$(expect_code "$(http_request GET "http://localhost:12114/api/v1/admin/federation/status")" "200")"
append_transcript "status-node-a" "${STATUS_A}"
[[ "${STATUS_A}" != *"${ADMIN_TOKEN}"* ]]
[[ "${STATUS_A}" != *"${CURSOR_SECRET}"* ]]
echo "Node A worker activation complete with single activation audit"

PUB_R2_PAYLOAD="$(uv run python - <<'PY' "${RUN_ID}"
import json
import sys
print(json.dumps({
    "localId": f"Demo-License-{sys.argv[1]}-R2",
    "version": "1",
    "payload": {"licenseId": f"Demo-License-{sys.argv[1]}-R2", "name": "Demo License R2"},
}))
PY
)"
PUBLISHED_R2="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/publish" "${PUB_R2_PAYLOAD}")" "200")"
append_transcript "published-r2" "${PUBLISHED_R2}"
CANONICAL_R2="$(json_get "${PUBLISHED_R2}" "canonicalId")"
ENC_CANONICAL_R2="$(url_encode "${CANONICAL_R2}")"
ENC_CANONICAL_R2_RECORD="$(encode_record_id "${CANONICAL_R2}")"
RECORD_R2_A="$(curl -fsS "http://localhost:12114/api/v1/federation/records/${ENC_CANONICAL_R2_RECORD}")"
append_transcript "record-r2-a" "${RECORD_R2_A}"
[[ "$(json_get "${RECORD_R2_A}" "signed.signature.kid")" == "${NODE_A_K2}" ]]

CURSOR_BEFORE_REJECT="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
SYNC_REJECT="$(sync_request "${PEER_ID}")"
append_transcript "sync-reject-a2-unapproved" "${SYNC_REJECT}"
SYNC_REJECT_STATUS="$(json_get "${SYNC_REJECT}" "status")"
[[ "${SYNC_REJECT_STATUS}" == "failed" || "${SYNC_REJECT_STATUS}" == "partial" ]]
CURSOR_AFTER_REJECT="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ "${CURSOR_AFTER_REJECT}" == "${CURSOR_BEFORE_REJECT}" ]]
[[ "${CURSOR_AFTER_REJECT}" != "" ]]
[[ "$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=${ENC_CANONICAL_R1}" | tr -d '\n')" == *'"resolutionOutcome":"imported"'* ]]
if curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=$(url_encode "${CANONICAL_R2}")" >/dev/null 2>&1; then
  echo "R2 should not resolve on B while A2 is unapproved." >&2
  exit 1
fi
echo "Unknown-key rejection on B preserved cursor and prior imports"

ATTEMPTS_AFTER_REJECT="$(expect_code "$(http_request GET "http://localhost:12124/api/v1/admin/federation/sync-attempts?limit=5&peerId=${PEER_ID}")" "200")"
append_transcript "sync-attempts-after-reject" "${ATTEMPTS_AFTER_REJECT}"
REJECT_CODE="$(json_get "${ATTEMPTS_AFTER_REJECT}" "items.0.errorCode")"
[[ "${#REJECT_CODE}" -le 64 ]]
[[ "${REJECT_CODE}" != *"/"* ]]

PEER_STATE_B="$(expect_code "$(http_request GET "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}")" "200")"
append_transcript "peer-state-b-after-reject" "${PEER_STATE_B}"
CIRCUIT_STATE="$(json_get "${PEER_STATE_B}" "circuitState")"
if [[ "${CIRCUIT_STATE}" == "open" ]]; then
  echo "B circuit opened after permanent trust failure: expected"
fi

CURSOR_BEFORE_BAD_APPROVAL="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
BAD_APPROVE_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_K2}"
import json
import sys
print(json.dumps({
    "kid": sys.argv[1],
    "expectedFingerprint": "sha256:" + ("0" * 64),
    "reason": "intentional mismatch for demo"
}))
PY
)"
BAD_APPROVE_RESP="$(http_request POST "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/keys/approve" "${BAD_APPROVE_PAYLOAD}")"
BAD_APPROVE_BODY="$(echo "${BAD_APPROVE_RESP}" | sed '$d')"
BAD_APPROVE_CODE="$(echo "${BAD_APPROVE_RESP}" | tail -n1)"
append_transcript "bad-approve-a2" "${BAD_APPROVE_BODY}"
[[ "${BAD_APPROVE_CODE}" == "422" ]]
CURSOR_AFTER_BAD_APPROVAL="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ "${CURSOR_AFTER_BAD_APPROVAL}" == "${CURSOR_BEFORE_BAD_APPROVAL}" ]]

APPROVE_A2_PAYLOAD="$(uv run python - <<'PY' "${NODE_A_K2}" "${INSPECTED_NEW_FPR}"
import json
import sys
print(json.dumps({
    "kid": sys.argv[1],
    "expectedFingerprint": sys.argv[2],
    "reason": "approve rotated key after fingerprint verification"
}))
PY
)"
APPROVE_A2_RESULT="$(expect_code "$(http_request POST "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/keys/approve" "${APPROVE_A2_PAYLOAD}")" "200")"
append_transcript "approve-a2" "${APPROVE_A2_RESULT}"
[[ "$(json_get "${APPROVE_A2_RESULT}" "kid")" == "${NODE_A_K2}" ]]
[[ "$(json_get "${APPROVE_A2_RESULT}" "status")" == "active" ]]
echo "Explicit A2 approval on B: passed"

if [[ "${CIRCUIT_STATE}" == "open" ]]; then
  RESET_PAYLOAD='{"reason":"clear permanent trust failure after explicit key approval"}'
  RESET_RESULT="$(expect_code "$(http_request POST "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/circuit/reset" "${RESET_PAYLOAD}")" "200")"
  append_transcript "reset-circuit-b" "${RESET_RESULT}"
  [[ "$(json_get "${RESET_RESULT}" "circuitState")" == "closed" ]]
fi

SYNC_ACCEPT_R2="$(sync_request "${PEER_ID}")"
append_transcript "sync-r2-after-approval" "${SYNC_ACCEPT_R2}"
[[ "$(json_get "${SYNC_ACCEPT_R2}" "status")" == "complete" ]]
CURSOR_AFTER_R2="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ "${CURSOR_AFTER_R2}" != "${CURSOR_BEFORE_REJECT}" ]]

RESOLUTION_R2_B="$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=${ENC_CANONICAL_R2}")"
append_transcript "resolution-r2-b" "${RESOLUTION_R2_B}"
[[ "$(json_get "${RESOLUTION_R2_B}" "resolutionOutcome")" == "imported" ]]
[[ "$(json_get "${RESOLUTION_R2_B}" "authorityNodeId")" == "${NODE_A_ID}" ]]

SYNC_ACCEPT_R2_REPEAT="$(sync_request "${PEER_ID}")"
append_transcript "sync-r2-repeat" "${SYNC_ACCEPT_R2_REPEAT}"
[[ "$(json_get "${SYNC_ACCEPT_R2_REPEAT}" "importedRecords")" == "0" ]]
echo "R2 synchronized after approval with no duplicates on repeat"

IMPORTS_B_ALL="$(expect_code "$(http_request GET "http://localhost:12124/api/v1/admin/federation/peers/${PEER_ID}/imports")" "200")"
append_transcript "imports-b-all" "${IMPORTS_B_ALL}"
[[ "$(json_get "${IMPORTS_B_ALL}" "items.0.isAuthoritative")" == "False" || "$(json_get "${IMPORTS_B_ALL}" "items.0.isAuthoritative")" == "false" ]]

R1_EVENT_B_FIELDS="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -At -F $'\t' -c "
SELECT ie.signed_payload_digest_sha256, ie.signature_kid, ie.signature_base64url, ie.signed_payload::text
FROM federation_inbound_events ie
WHERE ie.record_canonical_id = '${CANONICAL_R1}'
ORDER BY ie.remote_event_position DESC
LIMIT 1
")"
R1_DB_DIGEST="$(echo "${R1_EVENT_B_FIELDS}" | cut -f1)"
R1_DB_KID="$(echo "${R1_EVENT_B_FIELDS}" | cut -f2)"
R1_DB_SIG="$(echo "${R1_EVENT_B_FIELDS}" | cut -f3)"
R1_DB_SIGNED_PAYLOAD="$(echo "${R1_EVENT_B_FIELDS}" | cut -f4-)"
[[ "${R1_DB_DIGEST}" == "${R1_EVENT_DIGEST}" ]]
[[ "${R1_DB_KID}" == "${R1_SIG_KID}" ]]
[[ "${R1_DB_SIG}" == "${R1_SIG_VALUE}" ]]
uv run python - <<'PY' "${X_A1}" "${R1_DB_SIGNED_PAYLOAD}" "${R1_DB_SIG}" "${R1_DB_DIGEST}"
import base64
import hashlib
import json
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
x = sys.argv[1]
payload = json.loads(sys.argv[2])
sig = sys.argv[3]
expected_digest = sys.argv[4]
payload_bytes = canonicalize_to_bytes(payload)
digest = hashlib.sha256(payload_bytes).hexdigest()
assert digest == expected_digest
raw_x = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
raw_sig = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
Ed25519PublicKey.from_public_bytes(raw_x).verify(raw_sig, payload_bytes)
print("ok")
PY
echo "R1 historical A1 signature unchanged and verifiable"

RETIRE_ACTIVE_PAYLOAD='{"expectedState":"staged","reason":"attempt active retire must fail"}'
RETIRE_ACTIVE_RESP="$(http_request POST "http://localhost:12114/api/v1/admin/federation/signing-keys/${NODE_A_K2}/retire" "${RETIRE_ACTIVE_PAYLOAD}")"
RETIRE_ACTIVE_BODY="$(echo "${RETIRE_ACTIVE_RESP}" | sed '$d')"
RETIRE_ACTIVE_CODE="$(echo "${RETIRE_ACTIVE_RESP}" | tail -n1)"
append_transcript "retire-active-attempt" "${RETIRE_ACTIVE_BODY}"
[[ "${RETIRE_ACTIVE_CODE}" != "200" ]]

[[ "${JWKS_A_ACTIVATED}" == *"\"kid\":\"${NODE_A_K1}\""* ]]

docker compose restart node-a node-a-worker >/dev/null
wait_ready "http://localhost:12114/api/v1/ready" "Node A after restart"
DISCOVERY_A_RESTART="$(curl -fsS http://localhost:12114/.well-known/lfs)"
append_transcript "node-a-discovery-restart" "${DISCOVERY_A_RESTART}"
[[ "$(json_get "${DISCOVERY_A_RESTART}" "currentSigningKid")" == "${NODE_A_K2}" ]]

PUB_R3_PAYLOAD="$(uv run python - <<'PY' "${RUN_ID}"
import json
import sys
print(json.dumps({
    "localId": f"Demo-License-{sys.argv[1]}-R3",
    "version": "1",
    "payload": {"licenseId": f"Demo-License-{sys.argv[1]}-R3", "name": "Demo License R3"},
}))
PY
)"
PUBLISHED_R3="$(expect_code "$(http_request POST "http://localhost:12114/api/v1/admin/federation/publish" "${PUB_R3_PAYLOAD}")" "200")"
append_transcript "published-r3" "${PUBLISHED_R3}"
CANONICAL_R3="$(json_get "${PUBLISHED_R3}" "canonicalId")"
ENC_CANONICAL_R3="$(encode_record_id "${CANONICAL_R3}")"
RECORD_R3_A="$(curl -fsS "http://localhost:12114/api/v1/federation/records/${ENC_CANONICAL_R3}")"
append_transcript "record-r3-a" "${RECORD_R3_A}"
[[ "$(json_get "${RECORD_R3_A}" "signed.signature.kid")" == "${NODE_A_K2}" ]]

ACTIVATION_AUDIT_COUNT_AFTER_RESTART="$(docker compose exec -T node-a-db psql -U postgres -d lfs_a -tAc "SELECT count(*) FROM federation_operational_audit WHERE action='local_key.activate' AND target_id='${NODE_A_K2}'" | tr -d '[:space:]')"
[[ "${ACTIVATION_AUDIT_COUNT_AFTER_RESTART}" == "1" ]]
echo "Restart persistence confirmed: A2 remains active"

TAMPER_EVENT_ID="$(uuidgen)"
TAMPER_RECORD_ID="$(docker compose exec -T node-a-db psql -U postgres -d lfs_a -tAc "SELECT id FROM federation_records ORDER BY created_at DESC LIMIT 1" | tr -d '[:space:]')"
LATEST_POSITION_A="$(docker compose exec -T node-a-db psql -U postgres -d lfs_a -tAc "SELECT COALESCE(MAX(event_sequence), 0) FROM federation_change_events" | tr -d '[:space:]')"
docker compose exec -T node-a-db psql -U postgres -d lfs_a -c "INSERT INTO federation_change_events (id, event_sequence, event_type, authority_node_id, record_id, operation, generated_at, payload_schema_version, signed_payload, signed_payload_digest_sha256, signature_base64url, signature_kid, signature_alg, provenance_type, event_payload, event_digest_sha256, occurred_at, created_at) VALUES ('${TAMPER_EVENT_ID}', ${LATEST_POSITION_A} + 1, 'record.changed', '${NODE_A_ID}', '${TAMPER_RECORD_ID}', 'upsert', NOW(), '1', '{\"tampered\":true}'::jsonb, 'bad', 'tampered', '${NODE_A_K2}', 'EdDSA', 'publication', '{}'::jsonb, 'bad', NOW(), NOW());" >/dev/null
CURSOR_BEFORE_TAMPER="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
TAMPER_SYNC="$(sync_request "${PEER_ID}")"
append_transcript "sync-after-tamper" "${TAMPER_SYNC}"
[[ "$(json_get "${TAMPER_SYNC}" "status")" != "complete" ]]
[[ "$(json_get "${TAMPER_SYNC}" "importedRecords")" == "0" ]]
CURSOR_AFTER_TAMPER="$(docker compose exec -T node-b-db psql -U postgres -d lfs_b -tAc "SELECT COALESCE((SELECT cursor FROM federation_peer_cursors WHERE peer_id='${PEER_ID}' ORDER BY updated_at DESC LIMIT 1), '')" | tr -d '[:space:]')"
[[ "${CURSOR_AFTER_TAMPER}" == "${CURSOR_BEFORE_TAMPER}" ]]
echo "Tamper rejection and cursor immutability: passed"

docker compose stop node-a >/dev/null
SYNC_OFFLINE="$(sync_request "${PEER_ID}")"
append_transcript "sync-offline" "${SYNC_OFFLINE}"
OFFLINE_STATUS="$(json_get "${SYNC_OFFLINE}" "status")"
[[ "${OFFLINE_STATUS}" == "partial" || "${OFFLINE_STATUS}" == "failed" ]]
RESOLUTION_OFFLINE="$(curl -fsS "http://localhost:12124/api/v1/licenses/resolution?identifier=${ENC_CANONICAL_R1}")"
append_transcript "resolution-offline-r1" "${RESOLUTION_OFFLINE}"
[[ "$(json_get "${RESOLUTION_OFFLINE}" "resolutionOutcome")" == "imported" ]]
[[ "$(json_get "${RESOLUTION_OFFLINE}" "freshnessState")" == "stale" ]]
[[ "$(json_get "${RESOLUTION_OFFLINE}" "sourceAvailability")" == "offline" ]]
docker compose start node-a >/dev/null
wait_ready "http://localhost:12114/api/v1/ready" "Node A restored"
echo "Offline imported-record behavior retained"

append_transcript "final-jwks-a" "$(curl -fsS http://localhost:12114/.well-known/jwks.json)"
append_transcript "final-status-node-b" "$(expect_code "$(http_request GET "http://localhost:12124/api/v1/admin/federation/status")" "200")"

if grep -Eq "BEGIN[[:space:]]+PRIVATE[[:space:]]+KEY|PRIVATE KEY-----|ENCRYPTED PRIVATE KEY" "${TRANSCRIPT}"; then
  echo "Leak scan failed: private key content marker found." >&2
  exit 1
fi
if grep -Fq "${ADMIN_TOKEN}" "${TRANSCRIPT}"; then
  echo "Leak scan failed: admin token found in transcript." >&2
  exit 1
fi
if grep -Fq "${CURSOR_SECRET}" "${TRANSCRIPT}"; then
  echo "Leak scan failed: cursor secret found in transcript." >&2
  exit 1
fi
if grep -Fq "${NODE_A_KEY_DIR}" "${TRANSCRIPT}" || grep -Fq "${NODE_B_KEY_DIR}" "${TRANSCRIPT}"; then
  echo "Leak scan failed: host key path found in transcript." >&2
  exit 1
fi

echo "Security leak scan: passed"
echo "Federation demo: PASSED"
