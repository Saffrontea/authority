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

install_network_agent() {
  local target_underlay target_host_key
  [[ "$(container_state "${TARGET_NAME}")" == "RUNNING" ]] || die "${TARGET_NAME} is not running"
  [[ -x "${NETWORK_AGENT_BINARY}" ]] || die "network agent binary missing; run cargo build -p authority-network-agent"
  [[ -s "${CONTROL_PLANE_PUBLIC_KEY}" ]] || die "control-plane public key is missing"
  local trusted_ca_file="${SSH_TRUSTED_CA_FILE}"
  if [[ ! -s "${trusted_ca_file}" ]]; then
    trusted_ca_file="${SSH_CA_PUBLIC_KEY}"
  fi
  [[ -s "${trusted_ca_file}" ]] || die "SSH CA trust bundle is missing"
  log "installing network-agent with container-held identity"
  as_root install -m 0755 "${NETWORK_AGENT_BINARY}" "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-network-agent.new"
  as_root mv -f "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-network-agent.new" \
    "${LXC_PATH}/${TARGET_NAME}/rootfs/usr/local/bin/authority-network-agent"
  as_root install -m 0644 "${CONTROL_PLANE_PUBLIC_KEY}" "${LXC_PATH}/${TARGET_NAME}/rootfs/etc/authority-control-plane.pub.pem"
  as_root install -m 0644 "${trusted_ca_file}" "${LXC_PATH}/${TARGET_NAME}/rootfs/etc/authority-ssh-ca.pub"
  attach "${TARGET_NAME}" sh -seu <<'CONTAINER_SCRIPT'
if ! command -v sshd >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends openssh-server
fi
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/sh deploy
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
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
EOF
sshd -t
systemctl enable ssh.service >/dev/null
systemctl restart ssh.service

cat > /etc/systemd/system/authority-network-agent.service <<EOF
[Unit]
Description=Authority WireGuard network grant agent
After=network-online.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
ExecStart=/usr/local/bin/authority-network-agent
Environment=AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE=/etc/authority-control-plane.pub.pem
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
  target_underlay="$(container_ip "${TARGET_NAME}")"
  target_host_key="$(attach "${TARGET_NAME}" cat /etc/ssh/ssh_host_ed25519_key.pub)"
  as_root install -d -m 0700 "$(dirname "${SSH_KNOWN_HOSTS_FILE}")"
  printf '%s %s\n' "${target_underlay}" "${target_host_key}" >"${SSH_KNOWN_HOSTS_FILE}"
  chmod 0644 "${SSH_KNOWN_HOSTS_FILE}"
  log "network-agent=http://${target_underlay}:3003"
}

network_agent_status() {
  local target_underlay
  target_underlay="$(container_ip "${TARGET_NAME}")"
  attach "${TARGET_NAME}" systemctl --no-pager --full status authority-network-agent.service || true
  attach "${TARGET_NAME}" systemctl --no-pager --full status ssh.service || true
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
    agent-status) network_agent_status ;;
    stop) stop_containers ;;
    destroy) destroy_containers ;;
    help | --help | -h) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
