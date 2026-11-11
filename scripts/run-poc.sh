#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_pid=''
issuer_pid=''
node_pid=''
cleaned_up=0
control_origin=${AUTHORITY_POC_CONTROL_ORIGIN:-http://localhost:3000}
issuer_origin=${AUTHORITY_POC_ISSUER_ORIGIN:-http://localhost:3001}
node_origin=${AUTHORITY_POC_NODE_ORIGIN:-http://localhost:3002}
AUTHORITY_TARGET_IDENTITY_FILE=${AUTHORITY_TARGET_IDENTITY_FILE:-${SCRIPT_DIR}/../.secrets/target-node-identity.json}

if [[ -z "${AUTHORITY_SSH_TARGET:-}" || -z "${AUTHORITY_POC_NETWORK_AGENT_ORIGIN:-}" || -z "${AUTHORITY_POC_WG_PUBLIC_KEY:-}" ]]; then
    mesh_status="$(mise run mesh:status)"
    if [[ -z "${AUTHORITY_SSH_TARGET:-}" ]]; then
        AUTHORITY_SSH_TARGET="$(
            printf '%s\n' "${mesh_status}" |
                awk '/^authority-target: RUNNING underlay=/ {
                    sub(/^.*underlay=/, "")
                    if ($0 != "none") print
                    exit
                }'
        )"
    fi
    if [[ -z "${AUTHORITY_SSH_TARGET}" ]]; then
        echo "poc:run: running authority-target LXC not found; run mise run mesh:setup" >&2
        exit 1
    fi
    if [[ -z "${AUTHORITY_POC_WG_PUBLIC_KEY:-}" ]]; then
        AUTHORITY_POC_WG_PUBLIC_KEY="$(
            printf '%s\n' "${mesh_status}" |
                awk '/^authority-client:/ { client = 1; next }
                     /^authority-target:/ { client = 0 }
                     client && /public-key:/ { print $2; exit }'
        )"
    fi
fi
if [[ -z "${AUTHORITY_POC_WG_PUBLIC_KEY:-}" ]]; then
    echo "poc:run: authority-client WireGuard key not found; run mise run mesh:setup" >&2
    exit 1
fi
AUTHORITY_POC_NETWORK_AGENT_ORIGIN=${AUTHORITY_POC_NETWORK_AGENT_ORIGIN:-http://${AUTHORITY_SSH_TARGET}:3003}
export AUTHORITY_SSH_TARGET AUTHORITY_POC_NETWORK_AGENT_ORIGIN AUTHORITY_POC_WG_PUBLIC_KEY AUTHORITY_TARGET_IDENTITY_FILE
echo "[poc] target=${AUTHORITY_SSH_TARGET} network-agent=${AUTHORITY_POC_NETWORK_AGENT_ORIGIN}" >&2

cleanup() {
    (( cleaned_up == 0 )) || return 0
    cleaned_up=1
    for pid in "${node_pid}" "${issuer_pid}" "${control_pid}"; do
        if [[ -n "${pid}" ]]; then
            kill "${pid}" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
}

on_signal() {
    trap - INT TERM
    cleanup
    exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

"${SCRIPT_DIR}/run-control-plane.sh" &
control_pid=$!

for _ in {1..300}; do
    if curl --fail --silent --show-error "${control_origin}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${control_pid}" 2>/dev/null || exit 1
    sleep 0.1
done
curl --fail --silent --show-error "${control_origin}/health" >/dev/null

"${SCRIPT_DIR}/run-credential-issuer.sh" &
issuer_pid=$!

for _ in {1..300}; do
    if curl --fail --silent --show-error "${issuer_origin}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${issuer_pid}" 2>/dev/null || exit 1
    sleep 0.1
done
curl --fail --silent --show-error "${issuer_origin}/health" >/dev/null

mise run mesh:agent:install
for _ in {1..100}; do
    if curl --fail --silent "${AUTHORITY_POC_NETWORK_AGENT_ORIGIN}/v1/identity" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl --fail --silent --show-error "${AUTHORITY_POC_NETWORK_AGENT_ORIGIN}/v1/identity" >/dev/null; then
    echo "poc:run: target node identity endpoint did not become ready" >&2
    exit 1
fi
target_identity_tmp="${AUTHORITY_TARGET_IDENTITY_FILE}.tmp.$$"
trap 'rm -f -- "${target_identity_tmp}"; cleanup' EXIT
curl --fail --silent --show-error "${AUTHORITY_POC_NETWORK_AGENT_ORIGIN}/v1/identity" >"${target_identity_tmp}"
chmod 0600 "${target_identity_tmp}"
mv -f -- "${target_identity_tmp}" "${AUTHORITY_TARGET_IDENTITY_FILE}"
echo "[poc] target node identity is ready" >&2

"${SCRIPT_DIR}/run-node-agent.sh" &
node_pid=$!

for _ in {1..300}; do
    if curl --fail --silent --show-error "${node_origin}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${node_pid}" 2>/dev/null || exit 1
    sleep 0.1
done
curl --fail --silent --show-error "${node_origin}/health" >/dev/null

echo "[poc] all services are ready" >&2

wait -n "${control_pid}" "${issuer_pid}" "${node_pid}"
