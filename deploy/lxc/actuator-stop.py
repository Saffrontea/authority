#!/usr/bin/python3
"""Independent systemd stop boundary, including watchdog/process crashes."""
import os
import subprocess

interface = os.environ.get('AUTHORITY_WIREGUARD_INTERFACE', 'wg0')

def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=2, **kwargs)

try:
    peers = run('/usr/local/lib/authority/wg-enforce', 'show', interface, 'peers').stdout.split()
    if peers:
        arguments = [item for peer in peers for item in ('peer', peer, 'remove')]
        run('/usr/local/lib/authority/wg-enforce', 'set', interface, *arguments)
    run('/usr/local/lib/authority/nft-observe', '-f', '-', input='flush set inet authority_tcp allowed\n')
except (OSError, subprocess.SubprocessError):
    # A broken mutation binary cannot leave stale mesh authority active. Startup
    # restores the interface only before clearing peers and obtaining fresh support.
    run('/usr/sbin/ip', 'link', 'set', 'dev', interface, 'down')
