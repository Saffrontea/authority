#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
AGENT="$SCRIPT_DIR/mise-agent.py"
BRIDGE="$SCRIPT_DIR/mise-agent-bridge.py"
SOCKET=${AUTHORITY_AGENT_SOCKET:-/tmp/authority-mise-agent.sock}
QUEUE=${AUTHORITY_AGENT_QUEUE:-/tmp/authority-mise-agent-queue-$(id -u)}
DEFAULT_PASSWORD_FILE="$PROJECT_DIR/.secrets/authority-db-password"

prepare_database_secret() {
    if [ -n "${AUTHORITY_DB_PASSWORD:-}" ] || [ -n "${AUTHORITY_DB_PASSWORD_FILE:-}" ]; then
        return
    fi

    install -d -m 0700 "$PROJECT_DIR/.secrets"
    if [ ! -s "$DEFAULT_PASSWORD_FILE" ]; then
        umask 077
        if command -v openssl >/dev/null 2>&1; then
            openssl rand -base64 32 >"$DEFAULT_PASSWORD_FILE"
        else
            od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$DEFAULT_PASSWORD_FILE"
            printf '\n' >>"$DEFAULT_PASSWORD_FILE"
        fi
        chmod 0600 "$DEFAULT_PASSWORD_FILE"
        echo "[authority-agent] generated local database secret" >&2
    fi
    AUTHORITY_DB_PASSWORD_FILE=$DEFAULT_PASSWORD_FILE
    export AUTHORITY_DB_PASSWORD_FILE
}

usage() {
    cat <<'EOF'
Usage: scripts/authority-agent.sh COMMAND [ARGUMENT ...]

Commands:
  serve             Start the privileged task agent in the foreground
  run TASK          Run an allowed internal mise task through the agent
  ping              Check whether the agent is available
  list              List tasks exposed by the agent
  cancel JOB        Cancel a running job
EOF
}

command=${1:-}
case "$command" in
    serve)
        prepare_database_secret
        operator=${AUTHORITY_AGENT_USER:-$(id -un)}
        mise_bin=$(command -v mise) || {
            echo "authority-agent: mise not found" >&2
            exit 1
        }
        "$BRIDGE" --socket "$SOCKET" --queue "$QUEUE" --agent "$AGENT" serve &
        bridge_pid=$!
        trap 'kill "$bridge_pid" 2>/dev/null || true; wait "$bridge_pid" 2>/dev/null || true' EXIT INT TERM
        "$PROJECT_DIR/deploy/lxc/sudo.sh" \
            "$AGENT" --socket "$SOCKET" serve \
            --project-dir "$PROJECT_DIR" \
            --mise "$mise_bin" \
            --owner "$operator" \
            --uid "$operator" \
            --run-as "$operator" \
            --allow '_db:*' \
            --allow '_mesh:*' \
            --root-task '_db:*' \
            --root-task '_mesh:*' \
            --max-jobs 1
        ;;
    run)
        shift
        [ "$#" -ge 1 ] || {
            usage >&2
            exit 2
        }
        exec "$BRIDGE" --socket "$SOCKET" --queue "$QUEUE" --agent "$AGENT" run "$@"
        ;;
    ping | list)
        exec "$BRIDGE" --socket "$SOCKET" --queue "$QUEUE" --agent "$AGENT" "$command"
        ;;
    cancel)
        shift
        [ "$#" -eq 1 ] || {
            usage >&2
            exit 2
        }
        exec "$BRIDGE" --socket "$SOCKET" --queue "$QUEUE" --agent "$AGENT" cancel "$1"
        ;;
    help | --help | -h)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
