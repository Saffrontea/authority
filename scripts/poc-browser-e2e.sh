#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly DRIVER_ORIGIN=http://127.0.0.1:9515
readonly ELEMENT_KEY=element-6066-11e4-a52e-4f735466cecf
driver_pid=''
session=''
log_file=''

cleanup() {
    if [[ -n "${session}" ]]; then
        curl --silent --request DELETE "${DRIVER_ORIGIN}/session/${session}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${driver_pid}" ]]; then
        kill "${driver_pid}" 2>/dev/null || true
        wait "${driver_pid}" 2>/dev/null || true
    fi
    [[ -z "${log_file}" || ! -f "${log_file}" ]] || rm -f "${log_file}"
}
trap cleanup EXIT INT TERM

die() {
    printf '[poc:e2e] error: %s\n' "$*" >&2
    if [[ -n "${log_file}" && -f "${log_file}" ]]; then
        cat "${log_file}" >&2
    fi
    exit 1
}

webdriver() {
    local method="$1" path="$2" body="${3:-}" response value_error
    if [[ -n "${body}" ]]; then
        response="$(curl --silent --show-error --max-time 15 \
            --request "${method}" --header 'content-type: application/json' \
            --data "${body}" "${DRIVER_ORIGIN}${path}")"
    else
        response="$(curl --silent --show-error --max-time 15 \
            --request "${method}" "${DRIVER_ORIGIN}${path}")"
    fi
    value_error="$(jq -r '.value.error? // empty' <<<"${response}")"
    [[ -z "${value_error}" ]] || die "WebDriver ${method} ${path}: ${response}"
    jq -c '.value // .' <<<"${response}"
}

find_element() {
    local selector="$1"
    webdriver POST "/session/${session}/element" \
        "$(jq -nc --arg selector "${selector}" '{using:"css selector",value:$selector}')" |
        jq -r --arg key "${ELEMENT_KEY}" '.[$key]'
}

set_value() {
    local selector="$1" value="$2" element
    element="$(find_element "${selector}")"
    webdriver POST "/session/${session}/element/${element}/clear" '{}' >/dev/null
    webdriver POST "/session/${session}/element/${element}/value" \
        "$(jq -nc --arg value "${value}" '{text:$value,value:($value|split(""))}')" >/dev/null
}

click() {
    local element
    element="$(find_element "$1")"
    webdriver POST "/session/${session}/element/${element}/click" '{}' >/dev/null
}

element_text() {
    local element
    element="$(find_element "$1")"
    webdriver GET "/session/${session}/element/${element}/text" | jq -r '.'
}

wait_for_result() {
    local prefix="$1" description="$2" value attempt
    for attempt in {1..150}; do
        value="$(element_text '#result')"
        if [[ "${value}" == "${prefix}"* ]]; then
            printf '%s\n' "${value}"
            return 0
        fi
        case "${value}" in
            '' | 'Ready.' | 'Waiting for authenticator…') ;;
            *) die "${description}: ${value}" ;;
        esac
        sleep 0.2
    done
    die "timed out waiting for ${description}"
}

json_post() {
    local url="$1" body="$2" authorization="${3:-}" response_file status
    response_file="$(mktemp)"
    if [[ -n "${authorization}" ]]; then
        status="$(curl --silent --show-error --output "${response_file}" --write-out '%{http_code}' \
            --request POST --header 'content-type: application/json' \
            --header "authorization: Bearer ${authorization}" --data "${body}" "${url}")"
    else
        status="$(curl --silent --show-error --output "${response_file}" --write-out '%{http_code}' \
            --request POST --header 'content-type: application/json' --data "${body}" "${url}")"
    fi
    if [[ ! "${status}" =~ ^2 ]]; then
        die "POST ${url}: HTTP ${status}: $(<"${response_file}")"
    fi
    cat "${response_file}"
    rm -f "${response_file}"
}

token="$(<"${PROJECT_DIR}/.secrets/authority-bootstrap-token")"
wireguard_public_key="${AUTHORITY_POC_WG_PUBLIC_KEY:-}"
network_agent_origin="${AUTHORITY_POC_NETWORK_AGENT_ORIGIN:-}"
control_origin="${AUTHORITY_POC_CONTROL_ORIGIN:-http://localhost:3000}"
issuer_origin="${AUTHORITY_POC_ISSUER_ORIGIN:-http://localhost:3001}"
node_origin="${AUTHORITY_POC_NODE_ORIGIN:-http://localhost:3002}"
log_file="$(mktemp)"

chromedriver --port=9515 --allowed-ips=127.0.0.1 --log-level=WARNING >"${log_file}" 2>&1 &
driver_pid=$!
printf '[poc:e2e] starting ChromeDriver\n'
for _ in {1..50}; do
    curl --silent --fail "${DRIVER_ORIGIN}/status" >/dev/null 2>&1 && break
    kill -0 "${driver_pid}" 2>/dev/null || die 'ChromeDriver exited during startup'
    sleep 0.2
done
curl --silent --fail "${DRIVER_ORIGIN}/status" >/dev/null || die 'ChromeDriver did not become ready'

capabilities="$(jq -nc '{capabilities:{alwaysMatch:{browserName:"chrome","webauthn:virtualAuthenticators":true,"goog:chromeOptions":{binary:"/usr/bin/chromium",args:["--headless=new","--disable-gpu","--disable-dev-shm-usage","--no-first-run"]}}}}')"
session="$(webdriver POST /session "${capabilities}" | jq -r '.sessionId')"
webdriver POST "/session/${session}/webauthn/authenticator" \
    '{"protocol":"ctap2","transport":"internal","hasResidentKey":true,"hasUserVerification":true,"isUserConsenting":true,"isUserVerified":true}' >/dev/null

query="issuer_origin=$(jq -rn --arg value "${issuer_origin}" '$value|@uri')&node_agent_origin=$(jq -rn --arg value "${node_origin}" '$value|@uri')"
if [[ -n "${wireguard_public_key}" ]]; then
    query+="&wireguard_public_key=$(jq -rn --arg value "${wireguard_public_key}" '$value|@uri')"
fi
page_url="${control_origin}/?${query}#bootstrap=${token}"
webdriver POST "/session/${session}/url" "$(jq -nc --arg url "${page_url}" '{url:$url}')" >/dev/null
set_value '#new-username' poc-e2e
set_value '#display-name' 'Automated PoC'
click '#register'
printf '[poc:e2e] waiting for Passkey registration\n'
registered="$(wait_for_result 'Passkey registered.' 'Passkey registration')"

if [[ -n "${wireguard_public_key}" ]]; then
    target_id="$(awk -F= '/^target=/ { print $2 }' <<<"${registered}")"
    [[ -n "${target_id}" ]] || die 'registration did not return target node id'
    install -d -m 0700 "${PROJECT_DIR}/.secrets"
    printf '%s\n' "${target_id}" >"${PROJECT_DIR}/.secrets/poc-mesh-target-node-id"
    chmod 0600 "${PROJECT_DIR}/.secrets/poc-mesh-target-node-id"
    mise run mesh:agent:install
    printf '[poc:e2e] target network-agent installed\n'
fi

click '#login'
printf '[poc:e2e] waiting for Passkey authentication and SSH issuance\n'
issued="$(wait_for_result 'Authenticated, authorized, and issued.' 'Passkey authentication and SSH issuance')"
ssh-keygen -L -f "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" | grep -q deploy ||
    die 'issued certificate does not contain the deploy principal'
printf '%s\n%s\n' "${registered}" "${issued}"

if [[ -n "${wireguard_public_key}" ]]; then
    prepared="$(webdriver POST "/session/${session}/execute/async" \
        '{"script":"const done = arguments[0]; window.authorityPrepareNetworkGrant().then(prepared => done({prepared})).catch(error => done({error: error.message}));","args":[]}')"
    prepare_error="$(jq -r '.error // empty' <<<"${prepared}")"
    [[ -z "${prepare_error}" ]] || die "network grant proof failed: ${prepare_error}"
    grant_body="$(jq -c '.prepared.body' <<<"${prepared}")"
    authorization="$(jq -r '.prepared.headers.authorization' <<<"${prepared}")"
    timestamp="$(jq -r '.prepared.headers["x-authority-timestamp"]' <<<"${prepared}")"
    nonce="$(jq -r '.prepared.headers["x-authority-nonce"]' <<<"${prepared}")"
    signature="$(jq -r '.prepared.headers["x-authority-device-signature"]' <<<"${prepared}")"
    grant_response="$(mktemp)"

    token_only_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' \
        --header "authorization: ${authorization}" --data "${grant_body}" \
        "${control_origin}/v1/network-access-grants")"
    [[ "${token_only_status}" == "401" ]] || die "token-only request returned HTTP ${token_only_status}"

    grant_status="$(curl --silent --output "${grant_response}" --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' \
        --header "authorization: ${authorization}" \
        --header "x-authority-timestamp: ${timestamp}" \
        --header "x-authority-nonce: ${nonce}" \
        --header "x-authority-device-signature: ${signature}" \
        --data "${grant_body}" "${control_origin}/v1/network-access-grants")"
    [[ "${grant_status}" == "200" ]] || die "device-bound request returned HTTP ${grant_status}: $(<"${grant_response}")"
    grant="$(<"${grant_response}")"

    replay_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' \
        --header "authorization: ${authorization}" \
        --header "x-authority-timestamp: ${timestamp}" \
        --header "x-authority-nonce: ${nonce}" \
        --header "x-authority-device-signature: ${signature}" \
        --data "${grant_body}" "${control_origin}/v1/network-access-grants")"
    rm -f "${grant_response}"
    [[ "${replay_status}" == "401" ]] || die "replayed device proof returned HTTP ${replay_status}"
    printf 'Session PoP: token-only denied, signed request accepted, replay denied\n'
    applied="$(json_post "${network_agent_origin}/v1/network-grants" "${grant}")"
    printf 'WireGuard peer applied.\npeer=%s\nallowed=%s\nexpires=%s\n' \
        "$(jq -r '.peer_public_key' <<<"${applied}")" \
        "$(jq -r '.allowed_ip' <<<"${applied}")" \
        "$(jq -r '.expires_at' <<<"${applied}")"
    ttl="${AUTHORITY_NETWORK_GRANT_TTL_SECONDS:-5}"
    printf '[poc:e2e] waiting %ss for grant expiry\n' "$((ttl + 2))"
    sleep "$((ttl + 2))"
    if mise run mesh:verify >/dev/null 2>&1; then
        die 'WireGuard peer remained active after grant expiry'
    fi
    printf 'WireGuard grant expiry: peer removed and tunnel denied\n'
    mise run mesh:configure
fi

printf 'OpenSSH certificate validation: OK\n'
