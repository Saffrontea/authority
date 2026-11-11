#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# == 3 ]] || {
    echo "usage: $0 URL ALLOWED_ORIGIN METHOD" >&2
    exit 2
}

readonly url="$1"
readonly allowed_origin="$2"
readonly method="$3"
readonly denied_origin='https://cors-denied.invalid'

response_origin() {
    curl --silent --show-error --dump-header - --output /dev/null \
        --request OPTIONS \
        --header "origin: $1" \
        --header "access-control-request-method: ${method}" \
        --header 'access-control-request-headers: content-type' \
        "${url}" |
        awk 'tolower($1) == "access-control-allow-origin:" { gsub(/\r/, "", $2); print $2; exit }'
}

actual_allowed="$(response_origin "${allowed_origin}")"
[[ "${actual_allowed}" == "${allowed_origin}" ]] || {
    echo "CORS allowlist rejected ${allowed_origin} for ${url}" >&2
    exit 1
}

actual_denied="$(response_origin "${denied_origin}")"
[[ -z "${actual_denied}" ]] || {
    echo "CORS allowlist exposed ${url} to ${denied_origin}" >&2
    exit 1
}
