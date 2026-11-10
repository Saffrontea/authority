#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SECRETS_DIR="$PROJECT_DIR/.secrets"
SSH_DIR="$SECRETS_DIR/poc-ssh"

AUTHORITY_SSH_CA_PUBLIC_KEY_FILE=${AUTHORITY_SSH_CA_PUBLIC_KEY_FILE:-$SECRETS_DIR/ssh-ca.pub}
AUTHORITY_NODE_SSH_KEY_FILE=${AUTHORITY_NODE_SSH_KEY_FILE:-$SSH_DIR/id_ed25519}
AUTHORITY_NODE_SSH_CERT_FILE=${AUTHORITY_NODE_SSH_CERT_FILE:-$SSH_DIR/id_ed25519-cert.pub}
export AUTHORITY_SSH_CA_PUBLIC_KEY_FILE AUTHORITY_NODE_SSH_KEY_FILE AUTHORITY_NODE_SSH_CERT_FILE

if [ ! -s "$AUTHORITY_SSH_CA_PUBLIC_KEY_FILE" ]; then
    echo "node-agent: SSH CA public key not found; start the issuer first" >&2
    exit 1
fi

exec cargo run --offline -p authority-node-agent
