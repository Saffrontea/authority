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
    jq -c 'if has("value") then .value else . end' <<<"${response}"
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

element_displayed() {
    local element
    element="$(find_element "$1")"
    webdriver GET "/session/${session}/element/${element}/displayed" | jq -r '.'
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
bootstrap_status="$(element_text '#bootstrap-status')"
[[ "${bootstrap_status}" == 'Bootstrap capability available.'* ]] ||
    die "bootstrap capability was not visible: ${bootstrap_status}"
[[ "$(element_displayed '#bootstrap-form')" == 'true' ]] ||
    die 'bootstrap form was hidden despite a valid bootstrap URL'
set_value '#new-username' poc-e2e
set_value '#display-name' 'Automated PoC'
click '#register'
printf '[poc:e2e] waiting for Passkey registration\n'
registered="$(wait_for_result 'Passkey registered.' 'Passkey registration')"
registered_user_id="$(awk -F= '/^user=/ { print $2 }' <<<"${registered}")"
bootstrap_status="$(element_text '#bootstrap-status')"
[[ "${bootstrap_status}" == *"user=${registered_user_id}"* ]] ||
    die "completed bootstrap identity was not visible: ${bootstrap_status}"
[[ "$(element_displayed '#bootstrap-form')" == 'false' ]] ||
    die 'consumed bootstrap form remained visible'

# A reload without the fragment must retain the non-secret identity summary,
# while never restoring the consumed bootstrap capability.
page_without_bootstrap="${control_origin}/?${query}"
webdriver POST "/session/${session}/url" \
    "$(jq -nc --arg url "${page_without_bootstrap}" '{url:$url}')" >/dev/null
bootstrap_status="$(element_text '#bootstrap-status')"
[[ "${bootstrap_status}" == 'Bootstrap completed.'* ]] ||
    die "bootstrap identity disappeared after reload: ${bootstrap_status}"
[[ "$(element_displayed '#bootstrap-form')" == 'false' ]] ||
    die 'bootstrap form reappeared after token consumption'
set_value '#username' poc-e2e
printf 'Bootstrap identity UI: capability, completion, and reload states verified\n'

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
issuer_ca="$(awk -F= '/^ca=/ { print $2 }' <<<"${issued}")"
[[ "${issuer_ca}" == SHA256:* ]] || die 'issued certificate did not report its CA fingerprint'
ssh-keygen -L -f "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" | grep -q deploy ||
    die 'issued certificate does not contain the deploy principal'
printf '%s\n%s\n' "${registered}" "${issued}"

certificate_only_body="$(jq -nc --rawfile certificate "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" '{certificate:$certificate}')"
certificate_only_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'content-type: application/json' --data "${certificate_only_body}" \
    "${node_origin}/v1/ssh-certificate")"
[[ "${certificate_only_status}" == "401" ]] ||
    die "node agent accepted certificate-only install with HTTP ${certificate_only_status}"

unauthorized_terminal_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --header 'Connection: Upgrade' --header 'Upgrade: websocket' \
    --header 'Sec-WebSocket-Version: 13' --header 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    --header "Origin: ${control_origin}" "${node_origin}/v1/ssh-terminal")"
[[ "${unauthorized_terminal_status}" == "403" ]] ||
    die "terminal without capability returned HTTP ${unauthorized_terminal_status}"

for legacy_route in /v1/issuance-authorizations /v1/network-access-grants; do
    legacy_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' --data '{}' \
        "${control_origin}${legacy_route}")"
    [[ "${legacy_status}" == "404" ]] || die "legacy route ${legacy_route} returned HTTP ${legacy_status}"
done
printf 'Local SSH boundary: certificate-only install denied, tokenless terminal denied, legacy routes absent\n'

terminal_command="$(webdriver POST "/session/${session}/execute/async" \
    '{"script":"const done = arguments[0]; window.authorityTerminalCommand(\"printf WEB_TERMINAL_OK\").then(() => done({ok:true})).catch(error => done({error:error.message}));","args":[]}')"
terminal_error="$(jq -r '.error // empty' <<<"${terminal_command}")"
[[ -z "${terminal_error}" ]] || die "web SSH terminal command failed: ${terminal_error}"
wait_for_terminal 'WEB_TERMINAL_OK' 'web SSH terminal command' >/dev/null
printf 'Web SSH terminal: signed certificate opened an interactive session\n'

ssh_target="${AUTHORITY_SSH_TARGET:-}"
ssh_target_port="${AUTHORITY_SSH_TARGET_PORT:-2222}"
[[ -n "${ssh_target}" ]] || die 'SSH mesh proxy target is not configured'
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
    -p "${ssh_target_port}"
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

    mismatched="$(webdriver POST "/session/${session}/execute/async" \
        '{"script":"const done = arguments[0]; window.authorityPrepareAccessAuthorization({wireguard_public_key:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}).then(prepared => done({prepared})).catch(error => done({error: error.message}));","args":[]}')"
    mismatch_error="$(jq -r '.error // empty' <<<"${mismatched}")"
    [[ -z "${mismatch_error}" ]] || die "mismatched WireGuard proof setup failed: ${mismatch_error}"
    mismatch_body="$(jq -c '.prepared.body' <<<"${mismatched}")"
    mismatch_authorization="$(jq -r '.prepared.headers.authorization' <<<"${mismatched}")"
    mismatch_timestamp="$(jq -r '.prepared.headers["x-authority-timestamp"]' <<<"${mismatched}")"
    mismatch_nonce="$(jq -r '.prepared.headers["x-authority-nonce"]' <<<"${mismatched}")"
    mismatch_signature="$(jq -r '.prepared.headers["x-authority-device-signature"]' <<<"${mismatched}")"
    mismatch_response="$(mktemp)"
    mismatch_status="$(curl --silent --output "${mismatch_response}" --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' \
        --header "authorization: ${mismatch_authorization}" \
        --header "x-authority-timestamp: ${mismatch_timestamp}" \
        --header "x-authority-nonce: ${mismatch_nonce}" \
        --header "x-authority-device-signature: ${mismatch_signature}" \
        --data "${mismatch_body}" "${control_origin}/v1/access-authorizations")"
    mismatch_reason="$(jq -r '.error // empty' <"${mismatch_response}")"
    rm -f "${mismatch_response}"
    [[ "${mismatch_status}" == "403" && "${mismatch_reason}" == "wireguard_key_mismatch" ]] ||
        die "mismatched WireGuard identity returned HTTP ${mismatch_status}: ${mismatch_reason}"
    printf 'Access deny boundary: signed WireGuard key mismatch rejected with a stable reason\n'

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

    prepared_revocation="$(webdriver POST "/session/${session}/execute/async" \
        "$(jq -nc --arg decision "${decision_id}" '{script:"const decision = arguments[0], done = arguments[1]; window.authorityPrepareRevocation(decision).then(prepared => done({prepared})).catch(error => done({error:error.message}));",args:[$decision]}')")"
    revocation_error="$(jq -r '.error // empty' <<<"${prepared_revocation}")"
    [[ -z "${revocation_error}" ]] || die "revocation proof failed: ${revocation_error}"
    revocation_body="$(jq -c '.prepared.body' <<<"${prepared_revocation}")"
    revocation_authorization="$(jq -r '.prepared.headers.authorization' <<<"${prepared_revocation}")"
    revocation_timestamp="$(jq -r '.prepared.headers["x-authority-timestamp"]' <<<"${prepared_revocation}")"
    revocation_nonce="$(jq -r '.prepared.headers["x-authority-nonce"]' <<<"${prepared_revocation}")"
    revocation_signature="$(jq -r '.prepared.headers["x-authority-device-signature"]' <<<"${prepared_revocation}")"
    revocation="$(curl --silent --fail --show-error --request POST \
        --header 'content-type: application/json' \
        --header "authorization: ${revocation_authorization}" \
        --header "x-authority-timestamp: ${revocation_timestamp}" \
        --header "x-authority-nonce: ${revocation_nonce}" \
        --header "x-authority-device-signature: ${revocation_signature}" \
        --data "${revocation_body}" \
        "${control_origin}/v1/access-authorizations/${decision_id}/revocations")"
    [[ "$(jq -r '.notice.decision_id' <<<"${revocation}")" == "${decision_id}" ]] ||
        die 'revocation notice did not bind the decision'

    pushed="$(json_post "${network_agent_origin}/v1/revocations" "${revocation}")"
    [[ "$(jq -r '.peer_removed' <<<"${pushed}")" == 'true' ]] ||
        die 'pushed revocation did not remove the active peer'
    if mise run mesh:verify >/dev/null 2>&1; then
        die 'WireGuard peer remained active after pushed revocation'
    fi
    if timeout 6 ssh "${ssh_options[@]}" \
        -o ConnectTimeout=3 \
        -i "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519" \
        -o "CertificateFile=${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" \
        "deploy@${ssh_target}" 'printf REVOKED_SSH_UNEXPECTED'; then
        die 'SSH over WireGuard reconnected after pushed revocation'
    fi
    printf 'SSH over WireGuard: reconnect denied immediately after push revocation\n'

    target_node_id="$(jq -r '.network_grant.grant.target_node_id' <<<"${decision}")"
    pulled_page="$(curl --silent --fail --show-error \
        "${control_origin}/v1/revocations?target_node_id=${target_node_id}&after=0")"
    pulled="$(jq -c --arg decision "${decision_id}" \
        '.notices[] | select(.notice.decision_id == $decision)' <<<"${pulled_page}")"
    [[ -n "${pulled}" ]] || die 'pull feed omitted the persisted revocation notice'
    reconciled="$(json_post "${network_agent_origin}/v1/revocations" "${pulled}")"
    [[ "$(jq -r '.peer_removed' <<<"${reconciled}")" == 'false' ]] ||
        die 'pull reconciliation was not idempotent'

    revoked_grant_response="$(mktemp)"
    revoked_grant_status="$(curl --silent --output "${revoked_grant_response}" --write-out '%{http_code}' \
        --request POST --header 'content-type: application/json' --data "${grant}" \
        "${network_agent_origin}/v1/network-grants")"
    revoked_grant_error="$(jq -r '.error // empty' <"${revoked_grant_response}")"
    rm -f "${revoked_grant_response}"
    [[ "${revoked_grant_status}" == '409' && "${revoked_grant_error}" == 'network_grant_revoked' ]] ||
        die "revoked grant was accepted: HTTP ${revoked_grant_status} ${revoked_grant_error}"
    printf 'Revocation distribution: push removed peer, pull reconciled idempotently, late grant denied\n'

    ttl="${AUTHORITY_NETWORK_GRANT_TTL_SECONDS:-5}"
    printf '[poc:e2e] waiting %ss for grant and notice expiry\n' "$((ttl + 2))"
    sleep "$((ttl + 2))"
    printf 'WireGuard grant expiry: revoked peer remained denied\n'
    sleep 4
    if ssh "${ssh_options[@]}" \
        -i "${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519" \
        -o "CertificateFile=${PROJECT_DIR}/.secrets/poc-ssh/id_ed25519-cert.pub" \
        "deploy@${ssh_target}" true; then
        die 'target accepted an expired SSH certificate'
    fi
    wait_for_terminal 'terminal transport error' 'expired web SSH terminal capability denial' >/dev/null
    printf 'OpenSSH certificate expiry: target denied expired certificate; node-agent denied expired terminal capability\n'
    mise run mesh:configure
fi

printf 'OpenSSH certificate validation: OK\n'
