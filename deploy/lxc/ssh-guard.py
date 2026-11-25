#!/usr/bin/python3
"""Root-only sshd principal command and per-connection systemd watchdog.

The watchdog service owns the sshd session's cgroup. Exiting, crashing, a missed
watchdog deadline, certificate expiry or agent shutdown therefore kills the whole
connection, including background descendants. PAM migration is disabled by the
managed sshd configuration, so session processes cannot leave that cgroup.
"""
import base64
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

SOCKET = '/run/authority-ssh/enforcement.sock'
PROGRAM = '/usr/local/lib/authority/ssh-guard.py'

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=4).stdout

def identity(key_id):
    if not key_id.startswith('authority-v2:') or len(key_id) > 4096:
        raise ValueError('unsupported SSH identity')
    encoded = key_id.removeprefix('authority-v2:')
    raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
    if base64.urlsafe_b64encode(raw).decode().rstrip('=') != encoded:
        raise ValueError('noncanonical SSH identity')
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('version') != 2:
        raise ValueError('unsupported SSH identity')
    return value

def process(pid):
    path = Path(f'/proc/{pid}')
    stat = path.joinpath('stat').read_text().rsplit(')', 1)[1].split()
    return int(stat[1]), int(stat[19])

def session_parent():
    listener = int(run('/usr/bin/systemctl', 'show', 'ssh.service', '-p', 'MainPID', '--value').strip())
    pid = os.getppid()
    for _ in range(4):
        parent, start = process(pid)
        executable = os.path.realpath(f'/proc/{pid}/exe')
        uid = Path(f'/proc/{pid}/status').read_text().split('Uid:', 1)[1].split()[0]
        if executable in ('/usr/sbin/sshd', '/usr/lib/openssh/sshd-session', '/usr/lib/openssh/sshd-auth') and uid == '0':
            if pid == listener:
                raise ValueError('refusing sshd listener')
            return pid, start
        pid = parent
    raise ValueError('principal command is not a root sshd child')

class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(1)
        self.sock.connect(SOCKET)

def request(path, body):
    connection = UnixConnection('localhost', timeout=1)
    try:
        connection.request('POST', path, json.dumps(body), {'content-type': 'application/json'})
        response = connection.getresponse()
        data = response.read(16385)
        if response.status != 200 or len(data) > 16384:
            raise ValueError('SSH enforcement unavailable or revoked')
        return json.loads(data)
    finally:
        connection.close()

def unit(pid, start):
    return f'authority-ssh-{pid}-{start}.service'

def notify(value):
    address = os.environ['NOTIFY_SOCKET']
    if address.startswith('@'):
        address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
        stream.connect(address)
        stream.sendall(value.encode())

def cgroup():
    lines = Path('/proc/self/cgroup').read_text().splitlines()
    group = next(line.removeprefix('0::') for line in lines if line.startswith('0::'))
    path = Path('/sys/fs/cgroup') / group.lstrip('/')
    if not path.name.startswith('authority-ssh-') or not path.name.endswith('.service'):
        raise ValueError('watchdog is outside its systemd service')
    return path

def attach_tree(pid, start, group):
    # The root sshd monitor is blocked waiting for this principal command.
    # Pin every process before moving it; the root session must still be current.
    descriptors = []
    try:
        root_fd = os.pidfd_open(pid)
        descriptors.append(root_fd)
        if process(pid)[1] != start:
            raise ValueError('SSH process changed')
        pending, members = [pid], []
        while pending:
            current = pending.pop()
            try:
                if current != pid:
                    descriptors.append(os.pidfd_open(current))
                pending.extend(map(int, Path(f'/proc/{current}/task/{current}/children').read_text().split()))
                members.append(current)
            except (FileNotFoundError, ProcessLookupError):
                continue
        for current in members:
            try:
                group.joinpath('cgroup.procs').write_text(str(current))
            except ProcessLookupError:
                continue
    finally:
        for descriptor in descriptors:
            os.close(descriptor)

def watch(key_id, pid, start):
    value = identity(key_id)
    deadline = time.monotonic() + max(0, value['expires_at'] - time.time())
    group = cgroup()
    attach_tree(pid, start, group)
    admitted = request('/ssh/admit', {'identity': value, 'pid': pid, 'start': start})
    token = admitted['token']
    lease_deadline = time.monotonic() + 2
    notify('READY=1\nWATCHDOG=1')
    while time.monotonic() < min(deadline, lease_deadline):
        try:
            if process(pid)[1] != start:
                break
            request('/ssh/renew', {'pid': pid, 'start': start, 'token': token})
            if time.monotonic() >= lease_deadline:
                break
            lease_deadline = time.monotonic() + 2
            notify('WATCHDOG=1')
        except FileNotFoundError:
            break
        except (OSError, ValueError):
            # Stop feeding systemd's watchdog until a fresh affirmative receipt.
            pass
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    group.joinpath('cgroup.kill').write_text('1')

def authorize(user, key_id):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('unsupported principal')
    if user not in Path(f'/etc/ssh/auth_principals/{user}').read_text().splitlines():
        raise ValueError('principal not configured')
    value = identity(key_id)
    pid, start = session_parent()
    name = unit(pid, start)
    if subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', name], check=False).returncode == 0:
        request('/ssh/admit', {'identity': value, 'pid': pid, 'start': start})
    else:
        remaining = max(1, int(value['expires_at'] - time.time()) + 1)
        run('/usr/bin/systemd-run', '--quiet', '--collect', '--unit', name,
            '--property=Type=notify', '--property=WatchdogSec=3s', '--property=TimeoutStartSec=4s',
            '--property=TimeoutStopSec=1s', '--property=KillMode=control-group',
            '--property=BindsTo=authority-network-agent.service', '--property=After=authority-network-agent.service',
            '--property=Restart=no', '--property=TasksMax=256', f'--property=RuntimeMaxSec={remaining}s',
            '--property=UMask=0077', '/usr/bin/python3', PROGRAM, 'watch', key_id, str(pid), str(start))
    print(user, flush=True)

if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit(1)
    try:
        if sys.argv[1] == 'authorize' and len(sys.argv) == 4:
            authorize(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == 'watch' and len(sys.argv) == 5:
            watch(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
        else:
            raise ValueError('invalid SSH guard command')
    except Exception as error:
        detail = str(error) if isinstance(error, (ValueError, OSError)) else "watchdog operation failed"
        print(f"SSH guard failed: {type(error).__name__}: {detail}", file=sys.stderr, flush=True)
        # No principal on failure; certificate material and lease tokens stay out
        # of public sshd error messages. systemd tears down a failed watchdog.
        raise SystemExit(1)
