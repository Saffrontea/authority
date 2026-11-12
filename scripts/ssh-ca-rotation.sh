#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly SECRETS_DIR="${AUTHORITY_CA_SECRETS_DIR:-${PROJECT_DIR}/.secrets}"
readonly ACTIVE_KEY="${SECRETS_DIR}/ssh-ca"
readonly ACTIVE_PUBLIC_KEY="${ACTIVE_KEY}.pub"
readonly NEXT_KEY="${SECRETS_DIR}/ssh-ca.next"
readonly NEXT_PUBLIC_KEY="${NEXT_KEY}.pub"
readonly PREVIOUS_KEY="${SECRETS_DIR}/ssh-ca.previous"
readonly PREVIOUS_PUBLIC_KEY="${PREVIOUS_KEY}.pub"
readonly TRUST_BUNDLE="${SECRETS_DIR}/ssh-trusted-user-cas.pub"
readonly STATE_FILE="${SECRETS_DIR}/ssh-ca-rotation-state"
readonly ACTIVATED_AT_FILE="${SECRETS_DIR}/ssh-ca-activated-at"
readonly MIN_OVERLAP_SECONDS="${AUTHORITY_CA_MIN_OVERLAP_SECONDS:-600}"

die() {
    printf '[ca:rotation] error: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -s "$1" ]] || die "required file is missing: $1"
}

fingerprint() {
    ssh-keygen -lf "$1" | awk '{ print $2 }'
}

write_bundle() {
    local temporary
    temporary="$(mktemp "${SECRETS_DIR}/.ssh-ca-trust.XXXXXX")"
    awk 'NF && !seen[$0]++' "$@" >"${temporary}"
    chmod 0644 "${temporary}"
    mv -f -- "${temporary}" "${TRUST_BUNDLE}"
}

write_state() {
    local temporary
    temporary="$(mktemp "${SECRETS_DIR}/.ssh-ca-state.XXXXXX")"
    printf '%s\n' "$1" >"${temporary}"
    chmod 0600 "${temporary}"
    mv -f -- "${temporary}" "${STATE_FILE}"
}

status() {
    local phase=idle key
    [[ ! -s "${STATE_FILE}" ]] || phase="$(<"${STATE_FILE}")"
    printf 'phase: %s\n' "${phase}"
    if [[ -s "${ACTIVE_PUBLIC_KEY}" ]]; then
        printf 'active: %s\n' "$(fingerprint "${ACTIVE_PUBLIC_KEY}")"
    else
        printf 'active: missing\n'
    fi
    [[ ! -s "${NEXT_PUBLIC_KEY}" ]] || printf 'next: %s\n' "$(fingerprint "${NEXT_PUBLIC_KEY}")"
    [[ ! -s "${PREVIOUS_PUBLIC_KEY}" ]] || printf 'previous: %s\n' "$(fingerprint "${PREVIOUS_PUBLIC_KEY}")"
    if [[ -s "${TRUST_BUNDLE}" ]]; then
        printf 'trusted:\n'
        while IFS= read -r key || [[ -n "${key}" ]]; do
            [[ -z "${key}" ]] || printf '  %s\n' "$(ssh-keygen -lf /dev/stdin <<<"${key}" | awk '{ print $2 }')"
        done <"${TRUST_BUNDLE}"
    fi
}

prepare() {
    require_file "${ACTIVE_KEY}"
    require_file "${ACTIVE_PUBLIC_KEY}"
    [[ ! -e "${NEXT_KEY}" && ! -e "${NEXT_PUBLIC_KEY}" ]] ||
        die 'next CA already exists; inspect ca:status before continuing'
    [[ ! -e "${PREVIOUS_KEY}" && ! -e "${PREVIOUS_PUBLIC_KEY}" ]] ||
        die 'a retained previous CA exists; archive it before starting another rotation'
    install -d -m 0700 "${SECRETS_DIR}"
    umask 077
    ssh-keygen -q -t ed25519 -N '' -C 'authority-ssh-ca-next' -f "${NEXT_KEY}"
    write_bundle "${ACTIVE_PUBLIC_KEY}" "${NEXT_PUBLIC_KEY}"
    write_state prepared
    printf '[ca:rotation] prepared overlap trust: %s -> %s\n' \
        "$(fingerprint "${ACTIVE_PUBLIC_KEY}")" "$(fingerprint "${NEXT_PUBLIC_KEY}")"
}

activate() {
    [[ "$(cat "${STATE_FILE}" 2>/dev/null || true)" == overlap-deployed ]] ||
        die 'overlap trust has not been deployed; run ca:deploy-trust first'
    require_file "${ACTIVE_KEY}"
    require_file "${ACTIVE_PUBLIC_KEY}"
    require_file "${NEXT_KEY}"
    require_file "${NEXT_PUBLIC_KEY}"
    [[ ! -e "${PREVIOUS_KEY}" && ! -e "${PREVIOUS_PUBLIC_KEY}" ]] ||
        die 'previous CA destination already exists'
    mv -- "${ACTIVE_KEY}" "${PREVIOUS_KEY}"
    mv -- "${ACTIVE_PUBLIC_KEY}" "${PREVIOUS_PUBLIC_KEY}"
    mv -- "${NEXT_KEY}" "${ACTIVE_KEY}"
    mv -- "${NEXT_PUBLIC_KEY}" "${ACTIVE_PUBLIC_KEY}"
    write_bundle "${PREVIOUS_PUBLIC_KEY}" "${ACTIVE_PUBLIC_KEY}"
    write_state active
    date +%s >"${ACTIVATED_AT_FILE}"
    chmod 0600 "${ACTIVATED_AT_FILE}"
    printf '[ca:rotation] activated new CA %s; restart issuer and node-agent\n' \
        "$(fingerprint "${ACTIVE_PUBLIC_KEY}")"
}

finalize() {
    local activated_at now
    [[ "$(cat "${STATE_FILE}" 2>/dev/null || true)" == active ]] ||
        die 'rotation is not active'
    require_file "${ACTIVE_KEY}"
    require_file "${ACTIVE_PUBLIC_KEY}"
    require_file "${PREVIOUS_KEY}"
    require_file "${PREVIOUS_PUBLIC_KEY}"
    require_file "${ACTIVATED_AT_FILE}"
    activated_at="$(<"${ACTIVATED_AT_FILE}")"
    now="$(date +%s)"
    [[ "${MIN_OVERLAP_SECONDS}" =~ ^[0-9]+$ ]] || die 'AUTHORITY_CA_MIN_OVERLAP_SECONDS must be an integer'
    (( now - activated_at >= MIN_OVERLAP_SECONDS )) ||
        die "overlap window has not elapsed (${MIN_OVERLAP_SECONDS}s required)"
    write_bundle "${ACTIVE_PUBLIC_KEY}"
    write_state finalized
    printf '[ca:rotation] finalized trust on %s; previous private key retained at %s\n' \
        "$(fingerprint "${ACTIVE_PUBLIC_KEY}")" "${PREVIOUS_KEY}"
}

mark_deployed() {
    case "$(cat "${STATE_FILE}" 2>/dev/null || true)" in
        prepared) write_state overlap-deployed ;;
        finalized) write_state finalized-deployed ;;
        *) die 'trust deployment is not expected in the current rotation phase' ;;
    esac
    printf '[ca:rotation] recorded successful trust bundle deployment\n'
}

case "${1:-}" in
    status) status ;;
    prepare) prepare ;;
    activate) activate ;;
    finalize) finalize ;;
    mark-deployed) mark_deployed ;;
    *) die 'usage: ssh-ca-rotation.sh {status|prepare|activate|finalize|mark-deployed}' ;;
esac
