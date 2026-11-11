#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
poc_pid=''
cleaned_up=0

mesh_status="$(mise run mesh:status)"
AUTHORITY_POC_WG_PUBLIC_KEY="$(printf '%s\n' "${mesh_status}" | awk '/public-key:/ { print $2; exit }')"
target_underlay="$(printf '%s\n' "${mesh_status}" | awk '/^authority-target:/ { sub(/^.*underlay=/, ""); print; exit }')"
[[ -n "${AUTHORITY_POC_WG_PUBLIC_KEY}" && -n "${target_underlay}" ]] || {
    echo "poc:e2e: WireGuard mesh is not ready; run mise run mesh:setup" >&2
    exit 1
}
AUTHORITY_POC_NETWORK_AGENT_ORIGIN="http://${target_underlay}:3003"
AUTHORITY_NETWORK_GRANT_TTL_SECONDS=5
AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS=10
AUTHORITY_BIND=127.0.0.1:3100
AUTHORITY_RP_ORIGIN=http://localhost:3100
AUTHORITY_ISSUER_BIND=127.0.0.1:3101
AUTHORITY_NODE_AGENT_BIND=127.0.0.1:3102
AUTHORITY_SSH_TARGET="${target_underlay}"
AUTHORITY_BROWSER_ORIGINS=http://localhost:3100
AUTHORITY_POC_CONTROL_ORIGIN=http://localhost:3100
AUTHORITY_POC_ISSUER_ORIGIN=http://localhost:3101
AUTHORITY_POC_NODE_ORIGIN=http://localhost:3102
export AUTHORITY_POC_WG_PUBLIC_KEY AUTHORITY_POC_NETWORK_AGENT_ORIGIN AUTHORITY_NETWORK_GRANT_TTL_SECONDS
export AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS
export AUTHORITY_BIND AUTHORITY_RP_ORIGIN AUTHORITY_ISSUER_BIND AUTHORITY_NODE_AGENT_BIND
export AUTHORITY_SSH_TARGET
export AUTHORITY_BROWSER_ORIGINS
export AUTHORITY_POC_CONTROL_ORIGIN AUTHORITY_POC_ISSUER_ORIGIN AUTHORITY_POC_NODE_ORIGIN

cleanup() {
    (( cleaned_up == 0 )) || return 0
    cleaned_up=1
    [[ -n "${poc_pid}" ]] || return 0

    # run-poc owns a separate session/process group. Stop cargo wrappers and
    # the service binaries together instead of only killing the outer shell.
    kill -TERM -- "-${poc_pid}" 2>/dev/null || true
    for _ in {1..50}; do
        kill -0 "${poc_pid}" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "${poc_pid}" 2>/dev/null; then
        kill -KILL -- "-${poc_pid}" 2>/dev/null || true
    fi
    wait "${poc_pid}" 2>/dev/null || true
}

on_signal() {
    trap - INT TERM
    cleanup
    exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

setsid "${SCRIPT_DIR}/run-poc.sh" &
poc_pid=$!

for _ in {1..600}; do
    if curl --fail --silent "${AUTHORITY_POC_CONTROL_ORIGIN}/health" >/dev/null 2>&1 \
        && curl --fail --silent "${AUTHORITY_POC_ISSUER_ORIGIN}/health" >/dev/null 2>&1 \
        && curl --fail --silent "${AUTHORITY_POC_NODE_ORIGIN}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${poc_pid}" 2>/dev/null || exit 1
    sleep 0.1
done

"${SCRIPT_DIR}/assert-cors.sh" \
    "${AUTHORITY_POC_ISSUER_ORIGIN}/v1/ssh-certificates" "${AUTHORITY_RP_ORIGIN}" POST
"${SCRIPT_DIR}/assert-cors.sh" \
    "${AUTHORITY_POC_NODE_ORIGIN}/v1/ssh-certificate" "${AUTHORITY_RP_ORIGIN}" POST
echo "[poc] issuer and node-agent CORS allowlists verified" >&2

# A pre-existing service can satisfy /health while the newly started binary is
# still compiling or has failed to bind. This route must exist in the current
# build; an empty unauthenticated request reaches it and returns 401.
grant_probe_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'content-type: application/json' \
    --data '{"device_id":"00000000-0000-0000-0000-000000000001","target_node_id":"00000000-0000-0000-0000-000000000002","ssh_public_key_fingerprint":"SHA256:test","wireguard_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","terminal_token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' \
    "${AUTHORITY_POC_CONTROL_ORIGIN}/v1/access-authorizations")"
if [[ "${grant_probe_status}" != "401" ]]; then
    echo "poc:e2e: expected current grant route (401), got HTTP ${grant_probe_status}" >&2
    echo "poc:e2e: stop any existing poc:run/control-plane process and retry" >&2
    exit 1
fi

"${SCRIPT_DIR}/poc-browser-e2e.sh"
