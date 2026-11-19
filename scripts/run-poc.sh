#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_pid=''
issuer_pid=''
node_pid=''
replica_pids=()
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
                awk '/^authority-client: RUNNING underlay=/ {
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
if [[ -z "${AUTHORITY_POC_NETWORK_AGENT_ORIGIN:-}" ]]; then
    target_underlay="$(printf '%s\n' "${mesh_status}" | awk '/^authority-target: RUNNING underlay=/ { sub(/^.*underlay=/, ""); print; exit }')"
    [[ -n "${target_underlay}" ]] || {
        echo "poc:run: authority-target LXC not found; run mise run mesh:setup" >&2
        exit 1
    }
    AUTHORITY_POC_NETWORK_AGENT_ORIGIN="http://${target_underlay}:3003"
fi
AUTHORITY_SSH_TARGET_PORT=${AUTHORITY_SSH_TARGET_PORT:-2222}
AUTHORITY_POC_MTLS_SERVICE_ORIGIN=${AUTHORITY_POC_MTLS_SERVICE_ORIGIN:-${AUTHORITY_POC_NETWORK_AGENT_ORIGIN%:3003}:3004}
export AUTHORITY_POC_MTLS_SERVICE_ORIGIN
export AUTHORITY_SSH_TARGET AUTHORITY_SSH_TARGET_PORT AUTHORITY_POC_NETWORK_AGENT_ORIGIN AUTHORITY_POC_WG_PUBLIC_KEY AUTHORITY_TARGET_IDENTITY_FILE
echo "[poc] ssh-mesh-proxy=${AUTHORITY_SSH_TARGET}:${AUTHORITY_SSH_TARGET_PORT} network-agent=${AUTHORITY_POC_NETWORK_AGENT_ORIGIN}" >&2

cleanup() {
    (( cleaned_up == 0 )) || return 0
    cleaned_up=1
    for pid in "${node_pid}" "${issuer_pid}" "${control_pid}" "${replica_pids[@]}"; do
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

# Build before health deadlines start; cargo run can otherwise wait on unrelated
# test/clippy build locks while an apparently healthy process has not started.
if [[ "${AUTHORITY_POC_PREBUILT:-}" != 1 ]]; then
    cargo build --offline --workspace --bins
fi
AUTHORITY_POC_PREBUILT=1
export AUTHORITY_POC_PREBUILT
status="$("${SCRIPT_DIR}/authority-agent.sh" run _db:status)"
AUTHORITY_DB_HOST=${AUTHORITY_DB_HOST:-$(printf '%s\n' "$status" | awk '/^ip: / {print $2;exit}')}
AUTHORITY_DB_PASSWORD_FILE=${AUTHORITY_DB_PASSWORD_FILE:-${SCRIPT_DIR}/../.secrets/authority-db-password}
AUTHORITY_PKI_PUBLIC_ORIGIN=${AUTHORITY_PKI_PUBLIC_ORIGIN:-${issuer_origin/localhost/10.0.3.1}}
printf '%s\n' "$AUTHORITY_PKI_PUBLIC_ORIGIN" > "${SCRIPT_DIR}/../.secrets/pki-origin"
AUTHORITY_ISSUER_BIND=${AUTHORITY_ISSUER_BIND:-0.0.0.0:3001}
export AUTHORITY_ISSUER_BIND
export AUTHORITY_DB_HOST AUTHORITY_DB_PASSWORD_FILE AUTHORITY_PKI_PUBLIC_ORIGIN
if [[ "${AUTHORITY_POC_REPLICAS:-1}" == 2 ]]; then
    AUTHORITY_BIND=127.0.0.1:3200
    AUTHORITY_ISSUER_BIND=127.0.0.1:3301
    export AUTHORITY_BIND AUTHORITY_ISSUER_BIND
    python3 "${SCRIPT_DIR}/replica-proxy.py" 127.0.0.1:3100 127.0.0.1:3200 127.0.0.1:3201 &
    replica_pids+=("$!")
    python3 "${SCRIPT_DIR}/replica-proxy.py" 0.0.0.0:3101 127.0.0.1:3301 127.0.0.1:3302 &
    replica_pids+=("$!")
fi
"${SCRIPT_DIR}/run-control-plane.sh" &
control_pid=$!

for _ in {1..600}; do
    if curl --fail --silent --show-error "${control_origin}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${control_pid}" 2>/dev/null || exit 1
    sleep 0.1
done
curl --fail --silent --show-error "http://${AUTHORITY_BIND:-127.0.0.1:3000}/health" >/dev/null
if [[ "${AUTHORITY_POC_REPLICAS:-1}" == 2 ]]; then
    AUTHORITY_BIND=127.0.0.1:3201 "${SCRIPT_DIR}/run-control-plane.sh" &
    replica_pids+=("$!")
fi

"${SCRIPT_DIR}/run-credential-issuer.sh" &
issuer_pid=$!

for _ in {1..600}; do
    if curl --fail --silent --show-error "${issuer_origin}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${issuer_pid}" 2>/dev/null || exit 1
    sleep 0.1
done
# Probe the initialized first replica directly before starting its peer.
if [[ "${AUTHORITY_POC_REPLICAS:-1}" == 2 ]]; then
    curl --fail --silent --show-error http://127.0.0.1:3301/health >/dev/null
    AUTHORITY_ISSUER_BIND=127.0.0.1:3302 "${SCRIPT_DIR}/run-credential-issuer.sh" &
    replica_pids+=("$!")
    for _ in {1..100}; do
        curl --fail --silent http://127.0.0.1:3302/health >/dev/null && break
        sleep 0.1
    done
fi
curl --fail --silent --show-error "${issuer_origin}/health" >/dev/null

"${SCRIPT_DIR}/authority-agent.sh" run _mesh:agent-install
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

"${SCRIPT_DIR}/authority-agent.sh" run _mesh:mtls-install

"${SCRIPT_DIR}/run-node-agent.sh" &
node_pid=$!

for _ in {1..600}; do
    if curl --fail --silent --show-error "${node_origin}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "${node_pid}" 2>/dev/null || exit 1
    sleep 0.1
done
curl --fail --silent --show-error "${node_origin}/health" >/dev/null

if [[ "${AUTHORITY_POC_REPLICAS:-1}" == 2 ]]; then
    curl --fail --silent --show-error http://127.0.0.1:3201/health >/dev/null
fi
echo "[poc] all services are ready" >&2

wait -n "${control_pid}" "${issuer_pid}" "${node_pid}" "${replica_pids[@]}"
