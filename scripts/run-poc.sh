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
