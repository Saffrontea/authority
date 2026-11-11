#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly DRIVER_ORIGIN=http://127.0.0.1:9515
readonly ELEMENT_KEY=element-6066-11e4-a52e-4f735466cecf
driver_pid=''
session=''
log_file=''
plain_key=''

cleanup() {
    if [[ -n "${session}" ]]; then
        curl --silent --request DELETE "${DRIVER_ORIGIN}/session/${session}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${driver_pid}" ]]; then
        kill "${driver_pid}" 2>/dev/null || true
        wait "${driver_pid}" 2>/dev/null || true
    fi
    [[ -z "${log_file}" || ! -f "${log_file}" ]] || rm -f "${log_file}"
    [[ -z "${plain_key}" || ! -f "${plain_key}" ]] || rm -f "${plain_key}"
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

wait_for_terminal() {
    local pattern="$1" description="$2" value attempt
    for attempt in {1..100}; do
        value="$(element_text '#terminal-output')"
        if [[ "${value}" == *"${pattern}"* ]]; then
            printf '%s\n' "${value}"
            return 0
        fi
        sleep 0.1
    done
    die "timed out waiting for ${description}: ${value}"
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

if [[ -n "${wireguard_public_key}" ]]; then
    for _ in {1..50}; do
        curl --silent --fail "${network_agent_origin}/v1/identity" >/dev/null 2>&1 && break
        sleep 0.2
    done
    curl --silent --fail "${network_agent_origin}/v1/identity" >/dev/null ||
        die 'target network-agent identity endpoint did not become ready'
    "${SCRIPT_DIR}/assert-cors.sh" \
        "${network_agent_origin}/v1/network-grants" "${control_origin}" POST
    printf '[poc:e2e] target network-agent identity ready\n'
fi

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
    reported_target_id="$(curl --silent --fail "${network_agent_origin}/v1/identity" | jq -r '.node_id')"
    [[ "${target_id}" == "${reported_target_id}" ]] || die 'registered target does not match LXC-held identity'
    printf '[poc:e2e] target network-agent identity registered\n'
fi

click '#login'
printf '[poc:e2e] waiting for Passkey authentication and SSH issuance\n'
issued="$(wait_for_result 'Authenticated, authorized, and issued.' 'Passkey authentication and SSH issuance')"
ssh-keygen -L -f "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" | grep -q deploy ||
    die 'issued certificate does not contain the deploy principal'
printf '%s\n%s\n' "${registered}" "${issued}"

terminal_command="$(webdriver POST "/session/${session}/execute/async" \
    '{"script":"const done = arguments[0]; window.authorityTerminalCommand(\"printf WEB_TERMINAL_OK\").then(() => done({ok:true})).catch(error => done({error:error.message}));","args":[]}')"
terminal_error="$(jq -r '.error // empty' <<<"${terminal_command}")"
[[ -z "${terminal_error}" ]] || die "web SSH terminal command failed: ${terminal_error}"
wait_for_terminal 'WEB_TERMINAL_OK' 'web SSH terminal command' >/dev/null
printf 'Web SSH terminal: signed certificate opened an interactive session\n'

ssh_target="${network_agent_origin#http://}"
ssh_target="${ssh_target%%:*}"
plain_key="$(mktemp)"
cp "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519" "${plain_key}"
chmod 0600 "${plain_key}"
ssh_options=(
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=${PROJECT_DIR}/.secrets/poc-ssh/known_hosts"
    -o LogLevel=ERROR
)
if ssh "${ssh_options[@]}" -i "${plain_key}" "deploy@${ssh_target}" true; then
    rm -f "${plain_key}"
    die 'target accepted the SSH key without an Authority certificate'
fi
rm -f "${plain_key}"
ssh_result="$(ssh "${ssh_options[@]}" \
    -i "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519" \
    -o "CertificateFile=${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" \
    "deploy@${ssh_target}" 'printf AUTHORITY_SSH_OK')"
[[ "${ssh_result}" == 'AUTHORITY_SSH_OK' ]] || die 'target did not accept the SSH certificate'
printf 'OpenSSH target enforcement: key-only denied, signed certificate accepted\n'

if [[ -n "${wireguard_public_key}" ]]; then
    prepared="$(webdriver POST "/session/${session}/execute/async" \
        '{"script":"const done = arguments[0]; window.authorityPrepareAccessAuthorization().then(prepared => done({prepared})).catch(error => done({error: error.message}));","args":[]}')"
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
        "${control_origin}/v1/access-authorizations")"
    [[ "${token_only_status}" == "401" ]] || die "token-only request returned HTTP ${token_only_status}"

    grant_status="$(curl --silent --output "${grant_response}" --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' \
        --header "authorization: ${authorization}" \
        --header "x-authority-timestamp: ${timestamp}" \
        --header "x-authority-nonce: ${nonce}" \
        --header "x-authority-device-signature: ${signature}" \
        --data "${grant_body}" "${control_origin}/v1/access-authorizations")"
    [[ "${grant_status}" == "200" ]] || die "device-bound request returned HTTP ${grant_status}: $(<"${grant_response}")"
    decision="$(<"${grant_response}")"
    grant="$(jq -c '.network_grant' <<<"${decision}")"
    decision_id="$(jq -r '.decision_id' <<<"${decision}")"
    ssh_decision_id="$(jq -r '.ssh_authorization.authorization.nonce' <<<"${decision}")"
    network_decision_id="$(jq -r '.network_grant.grant.nonce' <<<"${decision}")"
    [[ "${decision_id}" == "${ssh_decision_id}" && "${decision_id}" == "${network_decision_id}" ]] ||
        die 'SSH and WireGuard artifacts do not share the signed decision id'

    replay_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' \
        --header "authorization: ${authorization}" \
        --header "x-authority-timestamp: ${timestamp}" \
        --header "x-authority-nonce: ${nonce}" \
        --header "x-authority-device-signature: ${signature}" \
        --data "${grant_body}" "${control_origin}/v1/access-authorizations")"
    rm -f "${grant_response}"
    [[ "${replay_status}" == "401" ]] || die "replayed device proof returned HTTP ${replay_status}"
    printf 'Unified decision %s: token-only denied, signed request accepted, replay denied\n' "${decision_id}"
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
    sleep 4
    if ssh "${ssh_options[@]}" \
        -i "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519" \
        -o "CertificateFile=${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" \
        "deploy@${ssh_target}" true; then
        die 'target accepted an expired SSH certificate'
    fi
    wait_for_terminal 'Permission denied' 'expired web SSH terminal reconnect denial' >/dev/null
    printf 'OpenSSH certificate expiry: target denied expired certificate\n'
    mise run mesh:configure
fi

printf 'OpenSSH certificate validation: OK\n'
