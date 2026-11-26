#!/bin/sh
# Local demo provisioning only; the control-plane process receives the public key.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${AUTHORITY_OPERATOR_PUBLIC_KEY_FILE:-}" ]; then
    [ -s "$AUTHORITY_OPERATOR_PUBLIC_KEY_FILE" ] || { echo 'operator public key is missing' >&2; exit 1; }
    exit 0
fi
secret_dir="$script_dir/../.secrets"
private="$secret_dir/operator-ed25519.pem"
public="$secret_dir/operator-ed25519.pub.pem"
if [ -e "$private" ] || [ -e "$public" ]; then
    [ -s "$private" ] && [ -s "$public" ] || { echo 'incomplete operator key pair; refusing replacement' >&2; exit 1; }
    openssl pkey -in "$private" -pubout | cmp -s - "$public" || { echo 'operator key pair mismatch' >&2; exit 1; }
    exit 0
fi
install -d -m 0700 "$secret_dir"
umask 077
set -C
openssl genpkey -algorithm ED25519 > "$private"
openssl pkey -in "$private" -pubout > "$public"
