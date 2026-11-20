#!/usr/bin/env bash
# Test-only fault control for the existing LXC receiver; no production switches.
set -Eeuo pipefail
(( EUID == 0 )) || { echo 'lifecycle tests require the privileged task agent' >&2; exit 1; }
container="${AUTHORITY_MESH_TARGET:-authority-target}"
lxc_path="${AUTHORITY_LXC_PATH:-/var/lib/lxc}"
case "${1:-}" in
  wg-fail)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
systemctl is-active --quiet authority-network-agent.service
mode_file=/run/authority-e2e-wg-mode
if [ ! -f "$mode_file" ]; then
  stat -c '%a' /usr/bin/wg > "$mode_file"
fi
journalctl -u authority-network-agent.service -n 0 --show-cursor --no-pager |
  sed -n 's/^-- cursor: //p' > /run/authority-e2e-wg-cursor
test -s /run/authority-e2e-wg-cursor
chmod a-x /usr/bin/wg
CONTAINER
    ;;
  wg-restore)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
mode_file=/run/authority-e2e-wg-mode
if [ -f "$mode_file" ]; then
  mode=$(cat "$mode_file")
  case "$mode" in *[!0-7]*|'') exit 1 ;; esac
  chmod "$mode" /usr/bin/wg
  rm -f "$mode_file"
fi
rm -f /run/authority-e2e-wg-cursor
CONTAINER
    ;;
  nft-fail)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
systemctl is-active --quiet authority-network-agent.service
mode_file=/run/authority-e2e-nft-mode
if [ ! -f "$mode_file" ]; then stat -c '%a' /usr/sbin/nft > "$mode_file"; fi
chmod a-x /usr/sbin/nft
CONTAINER
    ;;
  nft-restore)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
mode_file=/run/authority-e2e-nft-mode
if [ -f "$mode_file" ]; then
  mode=$(cat "$mode_file")
  case "$mode" in *[!0-7]*|'') exit 1 ;; esac
  chmod "$mode" /usr/sbin/nft
  rm -f "$mode_file"
fi
CONTAINER
    ;;
  peer-present)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
peers=$(wg show wg0 peers)
if [ -n "$peers" ]; then
  echo 'authority-e2e-peer=present'
else
  echo 'authority-e2e-peer=absent'
fi
CONTAINER
    ;;
  wg-expiry-observed)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
cursor=$(cat /run/authority-e2e-wg-cursor)
journalctl -u authority-network-agent.service --after-cursor="$cursor" --no-pager -o cat |
  grep -F 'failed to expire WireGuard peer; retrying' >/dev/null
CONTAINER
    ;;
  ledgers-compacted)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
started=$(systemctl show -p ExecMainStartTimestamp --value authority-network-agent.service)
cutoff=$(date -d "$started" +%s)
for ledger in /var/lib/authority/network-agent-replay-ledger /var/lib/authority/network-agent-revocations; do
  test -f "$ledger"
  awk -F '\t' -v cutoff="$cutoff" '
    NF != 2 || $1 !~ /^[0-9]+$/ || $1 <= cutoff { bad = 1 }
    END { exit bad }
  ' "$ledger"
done
echo 'startup ledger compaction verified without exposing stored nonces'
CONTAINER
    ;;
  crash)
    lxc-attach -P "${lxc_path}" -n "${container}" -- sh -seu <<'CONTAINER'
unit=authority-network-agent.service
old_pid=$(systemctl show -p MainPID --value "$unit")
old_restarts=$(systemctl show -p NRestarts --value "$unit")
test "$old_pid" -gt 0
systemctl kill --kill-whom=main --signal=SIGKILL "$unit"
for attempt in $(seq 1 100); do
  new_pid=$(systemctl show -p MainPID --value "$unit")
  restarts=$(systemctl show -p NRestarts --value "$unit")
  if [ "$new_pid" -gt 0 ] && [ "$new_pid" != "$old_pid" ] \
     && [ "$restarts" -gt "$old_restarts" ] \
     && systemctl is-active --quiet "$unit"; then
    printf 'SIGKILL observed: receiver PID changed and systemd NRestarts increased\n'
    exit 0
  fi
  sleep 0.1
done
echo 'receiver did not automatically recover from SIGKILL' >&2
exit 1
CONTAINER
    ;;
  *) echo 'expected nft-fail, nft-restore, wg-fail, wg-restore, wg-expiry-observed, peer-present, ledgers-compacted, or crash' >&2; exit 2 ;;
esac
