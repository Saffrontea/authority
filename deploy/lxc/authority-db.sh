#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly CONTAINER_NAME="${AUTHORITY_DB_CONTAINER:-authority-db}"
readonly LXC_PATH="${AUTHORITY_LXC_PATH:-/var/lib/lxc}"
readonly LXC_BRIDGE="${AUTHORITY_LXC_BRIDGE:-lxcbr0}"
readonly LXC_CONFIG="${SCRIPT_DIR}/authority-db.conf"
DATABASE_PASSWORD=''

log() {
  printf '[authority-db] %s\n' "$*"
}

die() {
  printf '[authority-db] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: deploy/lxc/authority-db.sh COMMAND

Commands:
  setup           Create, start, install, and initialize PostgreSQL
  create          Create the LXC container
  start           Start the container and wait for networking
  install         Install and initialize PostgreSQL in a running container
  migrate         Apply pending immutable SQL migrations
  status          Show container and PostgreSQL status
  verify          Verify database, role, SCRAM, and network settings
  verify-schema   Verify applied migration checksums and module schemas
  diagnose        Collect detailed LXC startup diagnostics
  shell           Open psql as the postgres administrator
  reset-password  Apply AUTHORITY_DB_PASSWORD to the authority role
  stop            Gracefully stop the container
  destroy         Stop and permanently delete the container (asks first)

Environment overrides:
  AUTHORITY_DB_CONTAINER   Container name (default: authority-db)
  AUTHORITY_LXC_PATH       LXC path (default: /var/lib/lxc)
  AUTHORITY_LXC_BRIDGE     Host bridge (default: lxcbr0)
  AUTHORITY_DB_PASSWORD    Required by setup, install, and reset-password
  AUTHORITY_DB_PASSWORD_FILE
                           Alternative file containing the password
  AUTHORITY_DB_FORCE=1     Skip the destroy confirmation
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

as_root() {
  (( EUID == 0 )) || die "must run as root; use a db:* mise task or deploy/lxc/sudo.sh"
  "$@"
}

require_host_namespace() {
  local inside_count outside_start
  read -r _ outside_start inside_count < /proc/self/uid_map
  if [[ "${outside_start}" == "0" && "${inside_count}" == "1" ]]; then
    die "this session has only one mapped UID; run this task from the host namespace"
  fi
}

load_database_password() {
  local password_file="${AUTHORITY_DB_PASSWORD_FILE:-}"

  if [[ -n "${AUTHORITY_DB_PASSWORD:-}" ]]; then
    DATABASE_PASSWORD="${AUTHORITY_DB_PASSWORD}"
  elif [[ -n "${password_file}" ]]; then
    [[ -r "${password_file}" ]] || die "password file is not readable: ${password_file}"
    DATABASE_PASSWORD="$(<"${password_file}")"
  else
    die "set AUTHORITY_DB_PASSWORD or AUTHORITY_DB_PASSWORD_FILE"
  fi

  [[ -n "${DATABASE_PASSWORD}" ]] || die "database password must not be empty"
  [[ "${DATABASE_PASSWORD}" != *$'\n'* ]] || die "database password must be one line"
}

validate_name() {
  [[ "${CONTAINER_NAME}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] ||
    die "invalid container name: ${CONTAINER_NAME}"
}

container_exists() {
  as_root test -f "${LXC_PATH}/${CONTAINER_NAME}/config"
}

container_state() {
  as_root lxc-info -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -sH 2>/dev/null || true
}

container_ip() {
  as_root lxc-info -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -iH 2>/dev/null |
    awk 'NF { print; exit }'
}

wait_for_ip() {
  local attempt ip_address
  for attempt in $(seq 1 60); do
    ip_address="$(container_ip)"
    if [[ -n "${ip_address}" ]]; then
      printf '%s\n' "${ip_address}"
      return 0
    fi
    sleep 1
  done
  die "container started but did not receive an address from ${LXC_BRIDGE}"
}

host_bridge_rule() {
  local bridge_cidr bridge_ip
  bridge_cidr="$(ip -4 -o address show dev "${LXC_BRIDGE}" scope global |
    awk 'NR == 1 { print $4 }')"
  [[ -n "${bridge_cidr}" ]] || die "no IPv4 address found on ${LXC_BRIDGE}"
  bridge_ip="${bridge_cidr%/*}"
  printf '%s/32\n' "${bridge_ip}"
}

create_container() {
  local architecture cache_path
  local -a template_args

  require_host_namespace
  require_command lxc-create
  require_command ip
  validate_name

  if container_exists; then
    # v1 of this setup created a root-owned container with a user idmap. It
    # cannot start because newuidmap validates allocations for root, not for
    # the invoking user. Recreate only that known-empty failed container.
    if as_root grep -q '^# Resolved at runtime for ' "${LXC_PATH}/${CONTAINER_NAME}/config"; then
      [[ "$(container_state)" != "RUNNING" ]] ||
        die "legacy container is running; refusing automatic replacement"
      if as_root test -d "${LXC_PATH}/${CONTAINER_NAME}/rootfs/var/lib/postgresql"; then
        die "legacy container contains PostgreSQL data; refusing automatic replacement"
      fi
      log "replacing failed legacy user-idmapped container"
      as_root lxc-destroy -P "${LXC_PATH}" -n "${CONTAINER_NAME}"
    else
      log "container ${CONTAINER_NAME} already exists"
      return 0
    fi
  fi

  ip link show "${LXC_BRIDGE}" >/dev/null 2>&1 ||
    die "LXC bridge ${LXC_BRIDGE} does not exist"

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

  log "creating ${CONTAINER_NAME}"
  as_root lxc-create \
    -P "${LXC_PATH}" \
    -n "${CONTAINER_NAME}" \
    -f "${LXC_CONFIG}" \
    -t download -- "${template_args[@]}"
}

start_container() {
  local state ip_address

  require_host_namespace
  require_command lxc-start
  require_command lxc-wait
  container_exists || die "container does not exist; run create first"

  state="$(container_state)"
  if [[ "${state}" != "RUNNING" ]]; then
    log "starting ${CONTAINER_NAME}"
    as_root lxc-start -P "${LXC_PATH}" -n "${CONTAINER_NAME}"
  fi

  as_root lxc-wait -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -s RUNNING
  ip_address="$(wait_for_ip)"
  log "container is running at ${ip_address}"
}

configure_postgres() {
  local host_rule="$1"

  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    sh -s -- "${host_rule}" <<'CONTAINER_SCRIPT'
set -eu
host_rule="$1"

hba_file="$(runuser -u postgres -- psql -Atqc 'SHOW hba_file')"

runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<'SQL'
ALTER SYSTEM SET listen_addresses = '*';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SQL

sed -i '/^# BEGIN AUTHORITY MANAGED$/,/^# END AUTHORITY MANAGED$/d' "${hba_file}"
{
  printf '\n# BEGIN AUTHORITY MANAGED\n'
  printf 'host authority authority %s scram-sha-256\n' "${host_rule}"
  printf '# END AUTHORITY MANAGED\n'
} >> "${hba_file}"

systemctl restart postgresql
CONTAINER_SCRIPT
}

provision_database() {
  local role_exists database_exists

  role_exists="$(as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql -Atqc \
    "SELECT 1 FROM pg_roles WHERE rolname = 'authority'")"

  if [[ "${role_exists}" != "1" ]]; then
    log "creating database role authority"
    as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
      runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c \
      'CREATE ROLE authority LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION'
  else
    log "database role authority already exists"
  fi

  set_database_password

  database_exists="$(as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql -Atqc \
    "SELECT 1 FROM pg_database WHERE datname = 'authority'")"

  if [[ "${database_exists}" != "1" ]]; then
    as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
      runuser -u postgres -- createdb --owner=authority authority
    log "created database authority"
  else
    log "database authority already exists"
  fi
}

set_database_password() {
  local escaped_password

  load_database_password
  escaped_password="${DATABASE_PASSWORD//\'/\'\'}"

  {
    printf 'SET standard_conforming_strings = on;\n'
    printf "ALTER ROLE authority PASSWORD '%s';\n" "${escaped_password}"
  } | as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql -v ON_ERROR_STOP=1

  DATABASE_PASSWORD=''
  escaped_password=''
  unset AUTHORITY_DB_PASSWORD
  log "applied database password from the environment"
}

install_postgres() {
  local host_rule

  require_host_namespace
  require_command lxc-attach
  [[ "$(container_state)" == "RUNNING" ]] || die "container is not running"
  host_rule="$(host_bridge_rule)"

  log "installing PostgreSQL"
  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    apt-get update
  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql

  configure_postgres "${host_rule}"
  provision_database
  apply_migrations
  log "PostgreSQL accepts SCRAM connections from ${host_rule} only"
}

ensure_migration_table() {
  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d authority <<'SQL'
CREATE SCHEMA IF NOT EXISTS platform AUTHORIZATION authority;
ALTER SCHEMA platform OWNER TO authority;
CREATE TABLE IF NOT EXISTS platform.schema_migrations (
    version text PRIMARY KEY,
    checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE platform.schema_migrations OWNER TO authority;
SQL
}

apply_migrations() {
  local migration filename checksum applied_checksum

  [[ "$(container_state)" == "RUNNING" ]] || die "container is not running"
  python3 "${REPO_ROOT}/scripts/check-migrations.py"
  ensure_migration_table

  for migration in "${REPO_ROOT}"/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
    [[ -f "${migration}" ]] || die "no migration files found"
    filename="$(basename -- "${migration}")"
    checksum="$(sha256sum "${migration}" | awk '{print $1}')"
    applied_checksum="$(as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
      runuser -u postgres -- psql -d authority -Atqc \
      "SELECT checksum FROM platform.schema_migrations WHERE version = '${filename}'")"

    if [[ -n "${applied_checksum}" ]]; then
      [[ "${applied_checksum}" == "${checksum}" ]] ||
        die "applied migration checksum differs: ${filename}"
      log "migration already applied: ${filename}"
      continue
    fi

    log "applying migration: ${filename}"
    {
      printf 'BEGIN;\nSET LOCAL ROLE authority;\n'
      sed -n '1,$p' "${migration}"
      printf "\nINSERT INTO platform.schema_migrations (version, checksum) VALUES ('%s', '%s');\n" \
        "${filename}" "${checksum}"
      printf 'COMMIT;\n'
    } | as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
      runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d authority
  done
}

show_status() {
  local state ip_address

  if ! container_exists; then
    log "container ${CONTAINER_NAME} does not exist"
    return 1
  fi

  state="$(container_state)"
  ip_address="$(container_ip)"
  printf 'container: %s\nstate: %s\nip: %s\n' \
    "${CONTAINER_NAME}" "${state:-UNKNOWN}" "${ip_address:-unavailable}"

  if [[ "${state}" == "RUNNING" ]]; then
    as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
      sh -c 'command -v pg_isready >/dev/null && pg_isready || true'
  fi
}

diagnose_container() {
  local logfile state

  container_exists || die "container does not exist"
  logfile="$(mktemp /tmp/authority-db-lxc.XXXXXX.log)"
  state="$(container_state)"

  printf 'container: %s\nstate-before: %s\n' "${CONTAINER_NAME}" "${state:-UNKNOWN}"
  if [[ "${state}" != "RUNNING" ]]; then
    as_root lxc-start -P "${LXC_PATH}" -n "${CONTAINER_NAME}" \
      --logfile "${logfile}" --logpriority DEBUG || true
  fi
  printf '%s\n' '--- effective config ---'
  as_root sed -n '1,260p' "${LXC_PATH}/${CONTAINER_NAME}/config"
  printf '%s\n' '--- startup log ---'
  sed -n '1,320p' "${logfile}"
  unlink "${logfile}"
}

verify_postgres() {
  [[ "$(container_state)" == "RUNNING" ]] || die "container is not running"

  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -At <<'SQL'
SELECT 'database=' || datname || ',owner=' || pg_get_userbyid(datdba)
FROM pg_database
WHERE datname = 'authority' AND pg_get_userbyid(datdba) = 'authority';
SELECT 'role=authority,scram=true'
FROM pg_authid
WHERE rolname = 'authority' AND rolpassword LIKE 'SCRAM-SHA-256$%';
SELECT 'listen_addresses=' || current_setting('listen_addresses');
SELECT 'password_encryption=' || current_setting('password_encryption');
SQL

  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- sh -eu -c '
    hba_file=$(runuser -u postgres -- psql -Atqc "SHOW hba_file")
    grep -Fx "host authority authority $1 scram-sha-256" "$hba_file"
  ' sh "$(host_bridge_rule)"
}

verify_schema() {
  local expected actual

  [[ "$(container_state)" == "RUNNING" ]] || die "container is not running"
  python3 "${REPO_ROOT}/scripts/check-migrations.py"
  ensure_migration_table

  while IFS= read -r migration; do
    expected="$(sha256sum "${migration}" | awk '{print $1}')"
    actual="$(as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
      runuser -u postgres -- psql -d authority -Atqc \
      "SELECT checksum FROM platform.schema_migrations WHERE version = '$(basename -- "${migration}")'")"
    [[ "${actual}" == "${expected}" ]] ||
      die "migration is missing or changed: $(basename -- "${migration}")"
  done < <(find "${REPO_ROOT}/migrations" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' | sort)

  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d authority -At <<'SQL'
SELECT 'schemas=' || string_agg(schema_name, ',' ORDER BY schema_name)
FROM information_schema.schemata
WHERE schema_name IN ('audit', 'device', 'identity', 'issuer', 'outbox', 'platform', 'policy');
SELECT 'tables=' || count(*)
FROM information_schema.tables
WHERE table_schema IN ('audit', 'device', 'identity', 'issuer', 'outbox', 'platform', 'policy');
SELECT 'migrations=' || count(*) FROM platform.schema_migrations;
SQL
}

open_shell() {
  [[ "$(container_state)" == "RUNNING" ]] || die "container is not running"
  as_root lxc-attach -P "${LXC_PATH}" -n "${CONTAINER_NAME}" -- \
    runuser -u postgres -- psql authority
}

reset_password() {
  [[ "$(container_state)" == "RUNNING" ]] || die "container is not running"
  set_database_password
}

stop_container() {
  if ! container_exists; then
    log "container ${CONTAINER_NAME} does not exist"
    return 0
  fi
  if [[ "$(container_state)" == "RUNNING" ]]; then
    log "stopping ${CONTAINER_NAME}"
    as_root lxc-stop -P "${LXC_PATH}" -n "${CONTAINER_NAME}" --timeout 30
  else
    log "container ${CONTAINER_NAME} is already stopped"
  fi
}

destroy_container() {
  local answer

  require_host_namespace
  if ! container_exists; then
    log "container ${CONTAINER_NAME} does not exist"
    return 0
  fi

  if [[ "${AUTHORITY_DB_FORCE:-0}" != "1" ]]; then
    read -r -p "Permanently delete LXC container '${CONTAINER_NAME}'? [y/N] " answer
    [[ "${answer}" == "y" || "${answer}" == "Y" ]] || {
      log "destroy cancelled"
      return 0
    }
  fi

  stop_container
  as_root lxc-destroy -P "${LXC_PATH}" -n "${CONTAINER_NAME}"
  log "deleted ${CONTAINER_NAME}"
}

main() {
  local command="${1:-}"
  case "${command}" in
    setup)
      create_container
      start_container
      install_postgres
      show_status
      ;;
    create) create_container ;;
    start) start_container ;;
    install) install_postgres ;;
    migrate) apply_migrations ;;
    status) show_status ;;
    verify) verify_postgres ;;
    verify-schema) verify_schema ;;
    diagnose) diagnose_container ;;
    shell) open_shell ;;
    reset-password) reset_password ;;
    stop) stop_container ;;
    destroy) destroy_container ;;
    help | --help | -h) usage ;;
    *)
      usage >&2
      [[ -n "${command}" ]] && printf '\nUnknown command: %s\n' "${command}" >&2
      exit 2
      ;;
  esac
}

main "$@"
