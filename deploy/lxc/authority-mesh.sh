#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CLIENT_NAME="${AUTHORITY_MESH_CLIENT:-authority-client}"
readonly TARGET_NAME="${AUTHORITY_MESH_TARGET:-authority-target}"
readonly LXC_PATH="${AUTHORITY_LXC_PATH:-/var/lib/lxc}"
readonly LXC_BRIDGE="${AUTHORITY_LXC_BRIDGE:-lxcbr0}"
readonly LXC_CONFIG="${SCRIPT_DIR}/authority-mesh-node.conf"
readonly CLIENT_MESH_ADDRESS="10.77.0.1/32"
readonly TARGET_MESH_ADDRESS="10.77.0.2/32"
readonly CLIENT_MESH_IP="${CLIENT_MESH_ADDRESS%/*}"
readonly TARGET_MESH_IP="${TARGET_MESH_ADDRESS%/*}"
readonly WG_PORT=51820
readonly NETWORK_AGENT_BINARY="${REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}/target/debug/authority-network-agent"
readonly CONTROL_PLANE_PUBLIC_KEY="${REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}/.secrets/control-plane-ed25519.pub.pem"
readonly SSH_CA_PUBLIC_KEY="${REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}/.secrets/ssh-ca.pub"
readonly SSH_TRUSTED_CA_FILE="${AUTHORITY_SSH_TRUSTED_CA_FILE:-${REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}/.secrets/ssh-trusted-user-cas.pub}"
readonly SSH_KNOWN_HOSTS_FILE="${REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}/.secrets/poc-ssh/known_hosts"

log() {
  printf '[authority-mesh] %s\n' "$*"
}

die() {
  printf '[authority-mesh] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: deploy/lxc/authority-mesh.sh COMMAND

Commands:
  setup     Create two LXC nodes, install WireGuard, configure, and verify
  create    Create authority-client and authority-target
  start     Start both containers and wait for underlay addresses
  install   Install WireGuard tools and generate a key on each node
  configure Configure the wg0 peer pair
  status    Show container, interface, peer, and handshake state
  verify    Ping the target over WireGuard and require a handshake
  agent-install Install and start the network-agent in authority-target
  agent-status  Show network-agent service status and endpoint
  agent-restart Restart the existing network-agent and reset client handshake
  tcp-demo-install Install the two TCP admission E2E services
  client-reconnect Reset only the client cached WireGuard transport
  stop      Gracefully stop both containers
  destroy   Permanently delete both containers (asks first)

Environment overrides:
  AUTHORITY_MESH_CLIENT   Client container name (default: authority-client)
  AUTHORITY_MESH_TARGET   Target container name (default: authority-target)
  AUTHORITY_LXC_PATH      LXC path (default: /var/lib/lxc)
  AUTHORITY_LXC_BRIDGE    Underlay bridge (default: lxcbr0)
  AUTHORITY_MESH_FORCE=1  Skip the destroy confirmation
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

as_root() {
  (( EUID == 0 )) || die "must run as root; use a mesh:* mise task or deploy/lxc/sudo.sh"
  "$@"
}

require_host_namespace() {
  local inside_count outside_start
  read -r _ outside_start inside_count < /proc/self/uid_map
  if [[ "${outside_start}" == "0" && "${inside_count}" == "1" ]]; then
    die "this session has only one mapped UID; run this task from the host namespace"
  fi
}

validate_name() {
  local name="$1"
  [[ "${name}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] ||
    die "invalid container name: ${name}"
}

container_exists() {
  as_root test -f "${LXC_PATH}/$1/config"
}

container_state() {
  as_root lxc-info -P "${LXC_PATH}" -n "$1" -sH 2>/dev/null || true
}

container_ip() {
  as_root lxc-info -P "${LXC_PATH}" -n "$1" -iH 2>/dev/null |
    awk '/^[0-9]+\./ { print; exit }'
}

wait_for_ip() {
  local name="$1" attempt ip_address
  for attempt in $(seq 1 60); do
    ip_address="$(container_ip "${name}")"
    if [[ -n "${ip_address}" ]]; then
      printf '%s\n' "${ip_address}"
      return 0
    fi
    sleep 1
  done
  die "${name} did not receive an IPv4 address from ${LXC_BRIDGE}"
}

create_one() {
  local name="$1" architecture cache_path
  local -a template_args

  validate_name "${name}"
  if container_exists "${name}"; then
    log "container ${name} already exists"
    return 0
  fi

  case "$(uname -m)" in
    aarch64 | arm64) architecture=arm64 ;;
    x86_64 | amd64) architecture=amd64 ;;
    *) die "unsupported host architecture: $(uname -m)" ;;
  esac

  template_args=(-d debian -r trixie -a "${architecture}")
  cache_path="/var/cache/lxc/download/debian/trixie/${architecture}/default/rootfs.tar.xz"
  if [[ -r "${cache_path}" ]]; then
    template_args+=(--force-cache)
    log "using cached Debian trixie/${architecture} image"
  fi

  log "creating ${name}"
  as_root lxc-create -P "${LXC_PATH}" -n "${name}" -f "${LXC_CONFIG}" \
    -t download -- "${template_args[@]}"
}

create_containers() {
  require_host_namespace
  require_command lxc-create
  require_command ip
  ip link show "${LXC_BRIDGE}" >/dev/null 2>&1 ||
    die "LXC bridge ${LXC_BRIDGE} does not exist"
  create_one "${CLIENT_NAME}"
  create_one "${TARGET_NAME}"
}

start_one() {
  local name="$1"
  container_exists "${name}" || die "container ${name} does not exist; run create first"
  if [[ "$(container_state "${name}")" != "RUNNING" ]]; then
    log "starting ${name}"
    as_root lxc-start -P "${LXC_PATH}" -n "${name}"
  fi
  as_root lxc-wait -P "${LXC_PATH}" -n "${name}" -s RUNNING
  log "${name} underlay=$(wait_for_ip "${name}")"
}

start_containers() {
  require_host_namespace
  require_command lxc-start
  require_command lxc-wait
  start_one "${CLIENT_NAME}"
  start_one "${TARGET_NAME}"
}

keys_exist() {
  [[ "$(container_state "${CLIENT_NAME}")" == "RUNNING" ]] &&
    [[ "$(container_state "${TARGET_NAME}")" == "RUNNING" ]] &&
    attach "${CLIENT_NAME}" test -s /etc/wireguard/public.key &&
    attach "${TARGET_NAME}" test -s /etc/wireguard/public.key
}

start_and_reconcile() {
  start_containers
  if keys_exist; then
    log "reconciling WireGuard endpoints with current underlay addresses"
    configure_mesh
  else
    log "WireGuard keys are not installed yet; skipping endpoint reconciliation"
  fi
}

attach() {
  local name="$1"
  shift
  as_root lxc-attach -P "${LXC_PATH}" -n "${name}" -- "$@"
}

load_wireguard_module() {
  if command -v modprobe >/dev/null 2>&1; then
    as_root modprobe wireguard
  elif [[ -x /sbin/modprobe ]]; then
    as_root /sbin/modprobe wireguard
  else
    log "modprobe not found; relying on kernel module autoload"
  fi
}

install_one() {
  local name="$1"
  [[ "$(container_state "${name}")" == "RUNNING" ]] || die "container ${name} is not running"
  log "installing WireGuard tools in ${name}"
  attach "${name}" env DEBIAN_FRONTEND=noninteractive apt-get update
  attach "${name}" env DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends wireguard-tools iproute2 iputils-ping
  attach "${name}" sh -eu -c '
    install -d -m 0700 /etc/wireguard
    if [ ! -s /etc/wireguard/private.key ]; then
      umask 077
      wg genkey > /etc/wireguard/private.key
      wg pubkey < /etc/wireguard/private.key > /etc/wireguard/public.key
    fi
    chmod 0600 /etc/wireguard/private.key
    chmod 0644 /etc/wireguard/public.key
  '
}

install_wireguard() {
  require_command lxc-attach
  load_wireguard_module
  install_one "${CLIENT_NAME}"
  install_one "${TARGET_NAME}"
}

public_key() {
  attach "$1" sh -eu -c 'cat /etc/wireguard/public.key'
}

configure_one() {
  local name="$1" local_address="$2" peer_public_key="$3" endpoint="$4" allowed_ip="$5"
  attach "${name}" sh -seu -- \
    "${local_address}" "${WG_PORT}" "${peer_public_key}" "${endpoint}" "${allowed_ip}" <<'CONTAINER_SCRIPT'
local_address="$1"
listen_port="$2"
peer_public_key="$3"
endpoint="$4"
allowed_ip="$5"
private_key="$(cat /etc/wireguard/private.key)"

umask 077
{
  printf '[Interface]\n'
  printf 'Address = %s\n' "${local_address}"
  printf 'ListenPort = %s\n' "${listen_port}"
  printf 'PrivateKey = %s\n\n' "${private_key}"
  printf '[Peer]\n'
  printf 'PublicKey = %s\n' "${peer_public_key}"
  printf 'Endpoint = %s\n' "${endpoint}"
  printf 'AllowedIPs = %s\n' "${allowed_ip}"
  printf 'PersistentKeepalive = 25\n'
} > /etc/wireguard/wg0.conf

wg-quick down wg0 >/dev/null 2>&1 || true
wg-quick up wg0
systemctl enable wg-quick@wg0.service >/dev/null 2>&1 || true
CONTAINER_SCRIPT
}

configure_mesh() {
  local client_underlay target_underlay client_public target_public
  client_underlay="$(container_ip "${CLIENT_NAME}")"
  target_underlay="$(container_ip "${TARGET_NAME}")"
  [[ -n "${client_underlay}" && -n "${target_underlay}" ]] ||
    die "both containers need underlay IPv4 addresses"
  client_public="$(public_key "${CLIENT_NAME}")"
  target_public="$(public_key "${TARGET_NAME}")"
  [[ -n "${client_public}" && -n "${target_public}" ]] || die "WireGuard keys are missing; run install"

  log "configuring ${CLIENT_NAME} (${CLIENT_MESH_ADDRESS}) -> ${TARGET_NAME}"
  configure_one "${CLIENT_NAME}" "${CLIENT_MESH_ADDRESS}" "${target_public}" \
    "${target_underlay}:${WG_PORT}" "${TARGET_MESH_ADDRESS}"
  log "configuring ${TARGET_NAME} (${TARGET_MESH_ADDRESS}) -> ${CLIENT_NAME}"
  configure_one "${TARGET_NAME}" "${TARGET_MESH_ADDRESS}" "${client_public}" \
    "${client_underlay}:${WG_PORT}" "${CLIENT_MESH_ADDRESS}"
}

show_one() {
  local name="$1" state ip_address
  if ! container_exists "${name}"; then
    printf '%s: ABSENT\n' "${name}"
    return
  fi
  state="$(container_state "${name}")"
  ip_address="$(container_ip "${name}")"
  printf '%s: %s underlay=%s\n' "${name}" "${state}" "${ip_address:-none}"
  if [[ "${state}" == "RUNNING" ]] && attach "${name}" test -e /etc/wireguard/public.key; then
    printf '  public-key: %s\n' "$(public_key "${name}")"
    attach "${name}" wg show wg0 2>/dev/null | sed 's/^/  /' || printf '  wg0: DOWN\n'
  fi
}

show_status() {
  show_one "${CLIENT_NAME}"
  show_one "${TARGET_NAME}"
}

verify_mesh() {
  local handshake
  [[ "$(container_state "${CLIENT_NAME}")" == "RUNNING" ]] || die "${CLIENT_NAME} is not running"
  [[ "$(container_state "${TARGET_NAME}")" == "RUNNING" ]] || die "${TARGET_NAME} is not running"
  log "pinging ${TARGET_MESH_IP} from ${CLIENT_NAME} over wg0"
  attach "${CLIENT_NAME}" ping -c 3 -W 2 "${TARGET_MESH_IP}"
  handshake="$(attach "${CLIENT_NAME}" wg show wg0 latest-handshakes | awk 'NR == 1 { print $2 }')"
  [[ "${handshake:-0}" =~ ^[0-9]+$ && "${handshake}" -gt 0 ]] || die "no WireGuard handshake observed"
  log "WireGuard tunnel verified (${CLIENT_MESH_IP} -> ${TARGET_MESH_IP})"
}

install_mtls_service() {
  local root="${REPO_ROOT:-$(cd -- "${SCRIPT_DIR}/../.." && pwd)}" target_underlay target_id
  target_underlay="$(container_ip "${TARGET_NAME}")"
  target_id="$(attach "${TARGET_NAME}" python3 -c 'import json,urllib.request; print(json.load(urllib.request.urlopen("http://127.0.0.1:3003/v1/identity"))["node_id"])')"
  [[ -n "${target_underlay}" && -n "${target_id}" ]] || die "target identity is unavailable"
  as_root install -m 0755 "${root}/target/debug/authority-mtls-service" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-mtls-service.new"
  as_root mv -f "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-mtls-service.new" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-mtls-service"
  as_root install -m 0644 "${root}/.secrets/mtls-ca-cert.pem" "${LXC_PATH}/${TARGET_NAME}/rootfs/etc/authority-mtls-client-ca.pem"
  as_root install -d "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/lib/authority"
  as_root install -m 0644 "${root}/scripts/tcp-fault-proxy.py" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/lib/authority/db-fault-proxy.py"
  as_root install -m 0600 "${root}/.secrets/authority-db-password" "${LXC_PATH}/${TARGET_NAME}/rootfs/etc/authority-db-password"
  local database_host pki_origin
  pki_origin="$(cat "${root}/.secrets/pki-origin")"
  [[ "${pki_origin}" =~ ^http://10\.0\.3\.1:[0-9]+$ ]] || die "invalid LXC PKI ingress origin"
  database_host="$(container_ip authority-db)"
  [[ -n "${database_host}" ]] || die "shared database is unavailable"
  # Admit only this trusted target's underlay /32, never the whole bridge subnet.
  attach authority-db sh -seu -- "${target_underlay}" <<'DATABASE_SCRIPT'
hba_file="$(runuser -u postgres -- psql -Atqc 'SHOW hba_file')"
sed -i '/^# BEGIN AUTHORITY MTLS TARGET$/,/^# END AUTHORITY MTLS TARGET$/d' "$hba_file"
{
  printf '\n# BEGIN AUTHORITY MTLS TARGET\n'
  printf 'host authority authority %s/32 scram-sha-256\n' "$1"
  printf '# END AUTHORITY MTLS TARGET\n'
} >> "$hba_file"
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()' >/dev/null
DATABASE_SCRIPT
  attach "${TARGET_NAME}" sh -seu <<CONTAINER_SCRIPT
umask 077
mkdir -p /var/lib/authority
refresh_server_certificate=0
if [ ! -s /var/lib/authority/mtls-server-key.pem ]; then
 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out /var/lib/authority/mtls-server-key.pem.new
 mv /var/lib/authority/mtls-server-key.pem.new /var/lib/authority/mtls-server-key.pem
 refresh_server_certificate=1
fi
# DHCP may assign a new underlay address after a container restart. Refresh the
# serving certificate while retaining the node's existing private key.
if [ "\${refresh_server_certificate}" = 1 ] \
 || [ ! -s /var/lib/authority/mtls-server-cert.pem ] \
 || ! openssl x509 -in /var/lib/authority/mtls-server-cert.pem -noout -checkip "${target_underlay}" >/dev/null 2>&1 \
 || ! openssl x509 -in /var/lib/authority/mtls-server-cert.pem -noout -checkend 0 >/dev/null 2>&1; then
 openssl req -x509 -new -key /var/lib/authority/mtls-server-key.pem -days 365 \
  -subj /CN=authority-target -addext basicConstraints=CA:FALSE -addext extendedKeyUsage=serverAuth -addext keyUsage=digitalSignature -addext subjectAltName=DNS:authority-target,IP:${target_underlay} \
  -out /var/lib/authority/mtls-server-cert.pem.new
 mv /var/lib/authority/mtls-server-cert.pem.new /var/lib/authority/mtls-server-cert.pem
fi
rm -f /run/authority-mtls-db-partition
cat > /etc/systemd/system/authority-mtls-db-proxy.service <<UNIT
[Unit]
Description=Authority LXC DB partition test transport
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/authority/db-fault-proxy.py ${database_host} 5432 15432 /run/authority-mtls-db-partition
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/authority-mtls-service.service <<UNIT
[Unit]
Description=Authority mTLS enforcing service
After=network-online.target authority-mtls-db-proxy.service
Requires=authority-mtls-db-proxy.service
[Service]
ExecStart=/usr/local/bin/authority-mtls-service
Environment=AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE=/etc/authority-control-plane.pub.pem
Environment=AUTHORITY_MTLS_CA_CERTIFICATE_FILE=/etc/authority-mtls-client-ca.pem
Environment=AUTHORITY_DB_HOST=${database_host}
Environment=AUTHORITY_DB_PASSWORD_FILE=/etc/authority-db-password
Environment=AUTHORITY_PKI_PUBLIC_ORIGIN=${pki_origin}
Environment=AUTHORITY_MTLS_OBSERVATION_SOCKET=/run/authority-observation/mtls-3004.sock
Environment=AUTHORITY_MTLS_SERVICE_KEY_FILE=/var/lib/authority/mtls-server-key.pem
Environment=AUTHORITY_MTLS_SERVICE_CERTIFICATE_FILE=/var/lib/authority/mtls-server-cert.pem
Environment=AUTHORITY_DOMAIN_ID=019a6e6d-4b01-7c31-bb4c-f83220bec001
Environment=AUTHORITY_TARGET_NODE_ID=${target_id}
Environment=AUTHORITY_MTLS_SERVICE_AUDIENCE=demo-api
Environment=AUTHORITY_MTLS_SERVICE_BIND=0.0.0.0:3004
Environment=AUTHORITY_MTLS_SERVICE_TLS_BIND=0.0.0.0:8443
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/authority /run/authority-observation
[Install]
WantedBy=multi-user.target
UNIT
sed -e 's/:3004/:3005/' -e 's/:8443/:8444/' -e 's/mtls-3004.sock/mtls-3005.sock/' /etc/systemd/system/authority-mtls-service.service > /etc/systemd/system/authority-mtls-service-2.service
sed -i -e 's/AUTHORITY_DB_HOST=${database_host}/AUTHORITY_DB_HOST=127.0.0.1/' /etc/systemd/system/authority-mtls-service.service
printf '\n[Service]\nEnvironment=AUTHORITY_DB_PORT=15432\n' >> /etc/systemd/system/authority-mtls-service.service
systemctl daemon-reload
systemctl enable authority-mtls-db-proxy.service >/dev/null
systemctl restart authority-mtls-db-proxy.service
systemctl enable authority-mtls-service-2.service >/dev/null
systemctl reset-failed authority-mtls-service-2.service
systemctl restart authority-mtls-service-2.service
systemctl enable authority-mtls-service.service >/dev/null
systemctl reset-failed authority-mtls-service.service
systemctl restart authority-mtls-service.service
CONTAINER_SCRIPT
  for port in 3004 3005; do
    for _ in {1..100}; do
      if attach "${TARGET_NAME}" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${port}/health',timeout=1)" 2>/dev/null; then break; fi
      sleep 0.1
    done
    attach "${TARGET_NAME}" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${port}/health',timeout=1)"
  done
  attach "${TARGET_NAME}" cat /var/lib/authority/mtls-server-cert.pem > "${root}/.secrets/mtls-server-cert.pem"
  as_root chown "$(stat -c '%u:%g' "${root}/.secrets/mtls-ca-cert.pem")" "${root}/.secrets/mtls-server-cert.pem"
}

install_network_agent() {
  local client_underlay target_underlay target_host_key
  [[ "$(container_state "${CLIENT_NAME}")" == "RUNNING" ]] || die "${CLIENT_NAME} is not running"
  [[ "$(container_state "${TARGET_NAME}")" == "RUNNING" ]] || die "${TARGET_NAME} is not running"
  [[ -x "${NETWORK_AGENT_BINARY}" ]] || die "network agent binary missing; run cargo build -p authority-network-agent"
  [[ -s "${CONTROL_PLANE_PUBLIC_KEY}" ]] || die "control-plane public key is missing"
  local trusted_ca_file="${SSH_TRUSTED_CA_FILE}"
  if [[ ! -s "${trusted_ca_file}" ]]; then
    trusted_ca_file="${SSH_CA_PUBLIC_KEY}"
  fi
  [[ -s "${trusted_ca_file}" ]] || die "SSH CA trust bundle is missing"
  attach "${CLIENT_NAME}" sh -seu <<'CONTAINER_SCRIPT'
proxy_binary=/usr/lib/systemd/systemd-socket-proxyd
test -x "${proxy_binary}"
systemctl stop authority-ssh-mesh-proxy.service authority-ssh-mesh-proxy.socket >/dev/null 2>&1 || true
systemctl stop 'authority-ssh-mesh-proxy@*.service' >/dev/null 2>&1 || true
cat > /etc/systemd/system/authority-ssh-mesh-proxy.socket <<'EOF'
[Unit]
Description=Authority SSH entry point into the WireGuard mesh
After=network-online.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Socket]
ListenStream=2222
Accept=no

[Install]
WantedBy=sockets.target
EOF
cat > /etc/systemd/system/authority-ssh-mesh-proxy.service <<EOF
[Unit]
Description=Authority SSH over WireGuard proxy
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
ExecStart=${proxy_binary} 10.77.0.2:22
EOF
systemctl daemon-reload
systemctl enable authority-ssh-mesh-proxy.socket >/dev/null
systemctl restart authority-ssh-mesh-proxy.socket
CONTAINER_SCRIPT
  log "installing network-agent with container-held identity"
  as_root install -d -m 0755 "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/lib/authority"
  attach "${TARGET_NAME}" install -m 0755 /usr/sbin/nft /usr/local/lib/authority/nft-observe
  as_root install -m 0755 "${SCRIPT_DIR}/endpoint-probe.py" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/lib/authority/endpoint-probe.py"
  as_root install -m 0755 "${SCRIPT_DIR}/ssh-guard.py" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/lib/authority/ssh-guard.py"
  as_root install -m 0755 "${SCRIPT_DIR}/actuator-stop.py" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/lib/authority/actuator-stop.py"
  as_root install -m 0755 "${NETWORK_AGENT_BINARY}" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-network-agent.new"
  as_root mv -f "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-network-agent.new" \
    "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-network-agent"
  as_root install -m 0644 "${CONTROL_PLANE_PUBLIC_KEY}" "${LXC_PATH}/${TARGET_NAME}/rootfs/etc/authority-control-plane.pub.pem"
  as_root install -m 0644 "${trusted_ca_file}" "${LXC_PATH}/${TARGET_NAME}/rootfs/etc/authority-ssh-ca.pub"
  attach "${TARGET_NAME}" sh -seu <<'CONTAINER_SCRIPT'
if ! command -v nft >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends nftables
fi
if ! command -v sshd >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends openssh-server
fi
install -m 0500 /usr/bin/wg /usr/local/lib/authority/wg-enforce
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/sh deploy
# A non-password account that OpenSSH can authenticate without PAM.
usermod -p '*' deploy
install -d -m 0755 /etc/ssh/auth_principals /etc/ssh/sshd_config.d
install -m 0644 /etc/authority-ssh-ca.pub /etc/ssh/authority-user-ca.pub
printf 'deploy\n' > /etc/ssh/auth_principals/deploy
chmod 0644 /etc/ssh/auth_principals/deploy /etc/ssh/authority-user-ca.pub
cat > /etc/ssh/sshd_config.d/authority.conf <<'EOF'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
TrustedUserCAKeys /etc/ssh/authority-user-ca.pub
AuthorizedKeysFile none
AuthorizedKeysCommand none
AuthorizedPrincipalsFile none
AuthorizedPrincipalsCommand /usr/local/lib/authority/ssh-guard.py authorize %u %i
AuthorizedPrincipalsCommandUser root
UsePAM no
EOF
sshd -t
install -d -m 0755 /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/authority-observation.conf <<'EOF'
[Service]
ExecStartPre=/usr/bin/python3 /usr/local/lib/authority/endpoint-probe.py ssh-before
ExecStartPost=/usr/bin/python3 /usr/local/lib/authority/endpoint-probe.py ssh-after
EOF
systemctl daemon-reload
systemctl enable ssh.service >/dev/null
systemctl restart ssh.service

cat > /etc/systemd/system/authority-network-agent.service <<EOF
[Unit]
Description=Authority WireGuard network grant agent
After=network-online.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
Type=notify
WatchdogSec=5s
TimeoutStopSec=5s
ExecStart=/usr/local/bin/authority-network-agent
ExecStopPost=/usr/bin/python3 /usr/local/lib/authority/actuator-stop.py
Environment=AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE=/etc/authority-control-plane.pub.pem
Environment=AUTHORITY_DOMAIN_ID=019a6e6d-4b01-7c31-bb4c-f83220bec001
Environment=AUTHORITY_WIREGUARD_INTERFACE=wg0
Environment=AUTHORITY_NETWORK_AGENT_REPLAY_LEDGER_FILE=/var/lib/authority/network-agent-replay-ledger
Environment=AUTHORITY_NETWORK_AGENT_IDENTITY_FILE=/var/lib/authority/node-identity.pem
Environment=AUTHORITY_BROWSER_ORIGINS=http://localhost:3000,http://localhost:3100
StateDirectory=authority
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable authority-network-agent.service >/dev/null
systemctl restart authority-network-agent.service
CONTAINER_SCRIPT
  # The agent clears target peers on startup. Reset the PoC client's cached
  # WireGuard session as well so its next authorized connection handshakes
  # immediately instead of reusing keys that the target has discarded.
  reconnect_client
  client_underlay="$(container_ip "${CLIENT_NAME}")"
  target_underlay="$(container_ip "${TARGET_NAME}")"
  target_host_key="$(attach "${TARGET_NAME}" cat /etc/ssh/ssh_host_ed25519_key.pub)"
  as_root install -d -m 0700 "$(dirname "${SSH_KNOWN_HOSTS_FILE}")"
  {
    printf '%s %s\n' "${target_underlay}" "${target_host_key}"
    printf '[%s]:2222 %s\n' "${client_underlay}" "${target_host_key}"
  } >"${SSH_KNOWN_HOSTS_FILE}"
  chmod 0644 "${SSH_KNOWN_HOSTS_FILE}"
  log "network-agent=http://${target_underlay}:3003 ssh-mesh-proxy=${client_underlay}:2222"
}

reconnect_client() {
  # Reset only the client's cached WireGuard session. Target-side membership
  # remains governed by the network agent's independently verified grant.
  attach "${CLIENT_NAME}" sh -seu <<'CONTAINER_SCRIPT'
wg-quick down wg0
wg-quick up wg0
CONTAINER_SCRIPT
}

install_tcp_demo() {
  attach "${TARGET_NAME}" sh -seu <<'CONTAINER_SCRIPT'
if ! command -v python3 >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends python3
fi
id authority-tcp-demo >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin authority-tcp-demo
install -d /usr/local/lib/authority
cat > /usr/local/lib/authority/tcp-demo.py <<'PYTHON'
import socketserver
import threading

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while chunk := self.request.recv(4096):
            self.request.sendall(chunk)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

for port in (8080, 8081):
    server = Server(('10.77.0.2', port), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
PYTHON
cat > /etc/systemd/system/authority-tcp-demo.service <<'UNIT'
[Unit]
Description=Authority TCP E2E echo services
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/authority/tcp-demo.py
User=authority-tcp-demo
Group=authority-tcp-demo
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable authority-tcp-demo.service
systemctl reset-failed authority-tcp-demo.service
systemctl restart authority-tcp-demo.service
CONTAINER_SCRIPT
  attach "${CLIENT_NAME}" sh -seu <<'CONTAINER_SCRIPT'
systemctl stop authority-tcp-demo-2223.service authority-tcp-demo-2224.service authority-tcp-demo-2223.socket authority-tcp-demo-2224.socket >/dev/null 2>&1 || true
for pair in 2223:8080 2224:8081; do
  listen=${pair%:*}
  target=${pair#*:}
  cat > "/etc/systemd/system/authority-tcp-demo-${listen}.socket" <<UNIT
[Unit]
Description=Authority TCP E2E mesh entry
After=wg-quick@wg0.service
[Socket]
ListenStream=${listen}
Accept=no
[Install]
WantedBy=sockets.target
UNIT
  cat > "/etc/systemd/system/authority-tcp-demo-${listen}.service" <<UNIT
[Unit]
Description=Authority TCP E2E proxy
After=wg-quick@wg0.service
[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd 10.77.0.2:${target}
UNIT
done
systemctl daemon-reload
systemctl restart authority-tcp-demo-2223.socket authority-tcp-demo-2224.socket
CONTAINER_SCRIPT
}

network_agent_status() {
  local target_underlay
  target_underlay="$(container_ip "${TARGET_NAME}")"
  attach "${CLIENT_NAME}" systemctl --no-pager --full status authority-ssh-mesh-proxy.socket || true
  attach "${CLIENT_NAME}" journalctl --no-pager -n 20 -u authority-ssh-mesh-proxy.service || true
  attach "${TARGET_NAME}" systemctl --no-pager --full status authority-network-agent.service || true
  attach "${TARGET_NAME}" systemctl --no-pager --full status ssh.service || true
  attach "${CLIENT_NAME}" wg show wg0 || true
  attach "${TARGET_NAME}" wg show wg0 || true
  attach "${TARGET_NAME}" nft list table inet authority_tcp || true
  attach "${TARGET_NAME}" ss -lnt || true
  attach "${CLIENT_NAME}" ip route get 10.77.0.2 || true
  attach "${TARGET_NAME}" systemctl --no-pager --full status authority-tcp-demo.service || true
  attach "${CLIENT_NAME}" systemctl --no-pager --full status authority-tcp-demo-2223.socket authority-tcp-demo-2223.service || true
  log "network-agent=http://${target_underlay}:3003"
}

stop_one() {
  local name="$1"
  if container_exists "${name}" && [[ "$(container_state "${name}")" == "RUNNING" ]]; then
    log "stopping ${name}"
    as_root lxc-stop -P "${LXC_PATH}" -n "${name}" --timeout 30
  fi
}

stop_containers() {
  stop_one "${CLIENT_NAME}"
  stop_one "${TARGET_NAME}"
}

destroy_containers() {
  local answer name
  require_host_namespace
  if [[ "${AUTHORITY_MESH_FORCE:-0}" != "1" ]]; then
    read -r -p "Permanently delete LXC containers '${CLIENT_NAME}' and '${TARGET_NAME}'? [y/N] " answer
    [[ "${answer}" == "y" || "${answer}" == "Y" ]] || {
      log "destroy cancelled"
      return 0
    }
  fi
  stop_containers
  for name in "${CLIENT_NAME}" "${TARGET_NAME}"; do
    if container_exists "${name}"; then
      as_root lxc-destroy -P "${LXC_PATH}" -n "${name}"
      log "deleted ${name}"
    fi
  done
}

main() {
  case "${1:-}" in
    setup)
      create_containers
      start_containers
      install_wireguard
      configure_mesh
      verify_mesh
      show_status
      ;;
    create) create_containers ;;
    start) start_and_reconcile ;;
    install) install_wireguard ;;
    configure) configure_mesh ;;
    status) show_status ;;
    verify) verify_mesh ;;
    agent-install) install_network_agent ;;
    mtls-install) install_mtls_service ;;
    mtls-status) attach "${TARGET_NAME}" journalctl -u authority-mtls-service.service --no-pager -n 40 ;;
    mtls-partition) attach "${TARGET_NAME}" touch /run/authority-mtls-db-partition ;;
    mtls-restore) attach "${TARGET_NAME}" rm -f /run/authority-mtls-db-partition ;;
    mtls-stop) attach "${TARGET_NAME}" systemctl stop authority-mtls-service.service authority-mtls-service-2.service ;;
    mtls-start) attach "${TARGET_NAME}" systemctl start authority-mtls-service.service authority-mtls-service-2.service ;;
    mtls-restart) attach "${TARGET_NAME}" systemctl restart authority-mtls-service.service authority-mtls-service-2.service ;;
    observation-break) attach "${TARGET_NAME}" /usr/sbin/nft flush chain inet authority_tcp inbound ;;
    ssh-guard-status)
      attach "${TARGET_NAME}" journalctl --since '-3min' -u ssh.service --no-pager -n 30
      attach "${TARGET_NAME}" journalctl --since '-3min' --grep 'SSH guard failed' --no-pager -n 20
      ;;
    agent-pid) attach "${TARGET_NAME}" systemctl show authority-network-agent.service --property MainPID --value ;;
    agent-status) network_agent_status ;;
    agent-restart)
      attach "${TARGET_NAME}" systemctl restart authority-network-agent.service
      reconnect_client
      ;;
    test-tcp-cidr)
      attach "${TARGET_NAME}" /usr/bin/python3 - <<'KERNEL'
import subprocess
nft = '/usr/sbin/nft'
table = 'authority_interval_test'
script = f"""add table inet {table}
add set inet {table} allowed {{ type ipv4_addr . ipv4_addr . inet_service; flags interval,timeout; }}
add element inet {table} allowed {{ 10.0.0.0-10.255.255.255 . 192.168.0.0-192.168.255.255 . 1024-65535 timeout 30s }}
"""
try:
    subprocess.run([nft,'-f','-'], input=script, text=True, check=True, capture_output=True)
    for source,target,port,expected in [
        ('10.0.0.0','192.168.0.0',1024,True),
        ('10.255.255.255','192.168.255.255',65535,True),
        ('10.77.0.1','192.168.2.3',8080,True),
        ('11.0.0.0','192.168.2.3',8080,False),
        ('10.77.0.1','192.169.2.3',8080,False),
        ('10.77.0.1','192.168.2.3',1023,False),
    ]:
        result = subprocess.run([nft,'get','element','inet',table,'allowed',f'{{ {source} . {target} . {port} }}'],capture_output=True)
        assert (result.returncode == 0) == expected, (source,target,port,result.stderr.decode())
    print('Kernel CIDR x CIDR x port range: boundary/interior membership and every outside axis verified')
finally:
    subprocess.run([nft,'delete','table','inet',table],check=True,capture_output=True)
KERNEL
      ;;
    test-tcp-wide)
      attach "${TARGET_NAME}" sh -eu -c 'mkdir -p /etc/systemd/system/authority-network-agent.service.d; printf "[Service]\nEnvironment=AUTHORITY_TCP_MANAGED_PORTS=8080-8180\n" > /etc/systemd/system/authority-network-agent.service.d/e2e-range.conf; systemctl daemon-reload; systemctl restart authority-network-agent.service'
      reconnect_client
      ;;
    test-tcp-normal)
      attach "${TARGET_NAME}" sh -eu -c 'rm -f /etc/systemd/system/authority-network-agent.service.d/e2e-range.conf; systemctl daemon-reload; systemctl restart authority-network-agent.service'
      reconnect_client
      ;;
    test-tcp-range-present)
      attach "${TARGET_NAME}" /usr/sbin/nft list set inet authority_tcp allowed | python3 -c 'import sys; s=sys.stdin.read(); assert "8080-8180" in s, "native nft interval is absent"; assert len(s) < 2048, "range expanded into points"'
      ;;
    tcp-demo-install) install_tcp_demo ;;
    client-reconnect) reconnect_client ;;
    stop) stop_containers ;;
    destroy) destroy_containers ;;
    help | --help | -h) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
