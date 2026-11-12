#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
rotation_tmp="$(mktemp -d /tmp/authority-ca-rotation-test.XXXXXX)"

cleanup() {
    case "${rotation_tmp}" in
        /tmp/authority-ca-rotation-test.*) rm -r -- "${rotation_tmp}" ;;
        *) printf 'refusing to remove unexpected test path: %s\n' "${rotation_tmp}" >&2 ;;
    esac
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -C authority-ssh-ca-current -f "${rotation_tmp}/ssh-ca"
old_fingerprint="$(ssh-keygen -lf "${rotation_tmp}/ssh-ca.pub" | awk '{ print $2 }')"

AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" "${SCRIPT_DIR}/ssh-ca-rotation.sh" prepare >/dev/null
[[ "$(awk 'NF { count++ } END { print count+0 }' "${rotation_tmp}/ssh-trusted-user-cas.pub")" -eq 2 ]]
if AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" "${SCRIPT_DIR}/ssh-ca-rotation.sh" activate >/dev/null 2>&1; then
    printf 'activation succeeded before overlap trust deployment\n' >&2
    exit 1
fi
AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" "${SCRIPT_DIR}/ssh-ca-rotation.sh" mark-deployed >/dev/null

AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" "${SCRIPT_DIR}/ssh-ca-rotation.sh" activate >/dev/null
new_fingerprint="$(ssh-keygen -lf "${rotation_tmp}/ssh-ca.pub" | awk '{ print $2 }')"
[[ "${old_fingerprint}" != "${new_fingerprint}" ]]
[[ "$(awk 'NF { count++ } END { print count+0 }' "${rotation_tmp}/ssh-trusted-user-cas.pub")" -eq 2 ]]
if AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" "${SCRIPT_DIR}/ssh-ca-rotation.sh" finalize >/dev/null 2>&1; then
    printf 'finalization succeeded before the overlap window elapsed\n' >&2
    exit 1
fi

AUTHORITY_CA_MIN_OVERLAP_SECONDS=0 AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" \
    "${SCRIPT_DIR}/ssh-ca-rotation.sh" finalize >/dev/null
[[ "$(awk 'NF { count++ } END { print count+0 }' "${rotation_tmp}/ssh-trusted-user-cas.pub")" -eq 1 ]]
[[ -s "${rotation_tmp}/ssh-ca.previous" ]]
[[ "$(ssh-keygen -lf "${rotation_tmp}/ssh-trusted-user-cas.pub" | awk '{ print $2 }')" == "${new_fingerprint}" ]]
AUTHORITY_CA_SECRETS_DIR="${rotation_tmp}" "${SCRIPT_DIR}/ssh-ca-rotation.sh" mark-deployed >/dev/null
[[ "$(<"${rotation_tmp}/ssh-ca-rotation-state")" == finalized-deployed ]]

printf 'SSH CA rotation: overlap, activation, retirement, and recovery key retention verified\n'
