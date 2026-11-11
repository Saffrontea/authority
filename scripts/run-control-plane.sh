#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SECRETS_DIR="$PROJECT_DIR/.secrets"
DEFAULT_DB_PASSWORD_FILE="$SECRETS_DIR/authority-db-password"
DEFAULT_BOOTSTRAP_TOKEN_FILE="$SECRETS_DIR/authority-bootstrap-token"
DEFAULT_SIGNING_KEY_FILE="$SECRETS_DIR/control-plane-ed25519.pem"
DEFAULT_SIGNING_PUBLIC_KEY_FILE="$SECRETS_DIR/control-plane-ed25519.pub.pem"
DEFAULT_TARGET_IDENTITY_FILE="$SECRETS_DIR/target-node-identity.json"

status=$($SCRIPT_DIR/authority-agent.sh run _db:status)
database_host=$(printf '%s\n' "$status" | awk '/^ip: / { print $2; exit }')
if [ -z "$database_host" ]; then
    printf '%s\n' "$status" >&2
    echo "control-plane: could not determine the database container address" >&2
    exit 1
fi

install -d -m 0700 "$SECRETS_DIR"
bootstrap_token_file=${AUTHORITY_BOOTSTRAP_TOKEN_FILE:-$DEFAULT_BOOTSTRAP_TOKEN_FILE}
if [ ! -s "$bootstrap_token_file" ]; then
    umask 077
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$bootstrap_token_file"
    printf '\n' >>"$bootstrap_token_file"
    chmod 0600 "$bootstrap_token_file"
    echo "[control-plane] generated local bootstrap token" >&2
fi

AUTHORITY_DB_HOST=${AUTHORITY_DB_HOST:-$database_host}
AUTHORITY_DB_PASSWORD_FILE=${AUTHORITY_DB_PASSWORD_FILE:-$DEFAULT_DB_PASSWORD_FILE}
AUTHORITY_BOOTSTRAP_TOKEN_FILE=$bootstrap_token_file
AUTHORITY_SIGNING_KEY_FILE=${AUTHORITY_SIGNING_KEY_FILE:-$DEFAULT_SIGNING_KEY_FILE}
AUTHORITY_SIGNING_PUBLIC_KEY_FILE=${AUTHORITY_SIGNING_PUBLIC_KEY_FILE:-$DEFAULT_SIGNING_PUBLIC_KEY_FILE}
AUTHORITY_TARGET_IDENTITY_FILE=${AUTHORITY_TARGET_IDENTITY_FILE:-$DEFAULT_TARGET_IDENTITY_FILE}
export AUTHORITY_DB_HOST AUTHORITY_DB_PASSWORD_FILE AUTHORITY_BOOTSTRAP_TOKEN_FILE AUTHORITY_SIGNING_KEY_FILE AUTHORITY_SIGNING_PUBLIC_KEY_FILE AUTHORITY_TARGET_IDENTITY_FILE

bootstrap_token=$(sed -n '1p' "$bootstrap_token_file")
bootstrap_query=''
if [ -n "${AUTHORITY_POC_WG_PUBLIC_KEY:-}" ]; then
    wireguard_public_key_encoded=$(jq -rn --arg value "$AUTHORITY_POC_WG_PUBLIC_KEY" '$value|@uri')
    bootstrap_query="?wireguard_public_key=${wireguard_public_key_encoded}"
fi
echo "[control-plane] bootstrap URL: ${AUTHORITY_RP_ORIGIN:-http://localhost:3000}/${bootstrap_query}#bootstrap=$bootstrap_token" >&2
unset bootstrap_token

exec cargo run --offline -p authority-control-plane
