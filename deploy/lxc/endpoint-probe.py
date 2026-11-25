#!/usr/bin/env python3
"""Root-owned target probe. Its stdout is signed by the Network Agent, not by Python."""
import base64
import glob
import hashlib
import http.client
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import socket
import stat

RECEIPT = Path('/run/authority-observation/ssh.json')

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=2).stdout

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def ssh_files():
    paths = set()
    def includes(path):
        path = Path(path)
        if str(path) in paths:
            return
        paths.add(str(path))
        for line in path.read_text().splitlines():
            fields = shlex.split(line, comments=True)
            if fields and fields[0].lower() == 'include':
                for pattern in fields[1:]:
                    if not pattern.startswith('/'):
                        pattern = '/etc/ssh/' + pattern
                    for child in glob.glob(pattern):
                        includes(child)
    includes('/etc/ssh/sshd_config')
    paths.update(['/etc/ssh/authority-user-ca.pub', '/etc/ssh/auth_principals/deploy'])
    return {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(paths)}

def process(unit):
    pid = int(run('/usr/bin/systemctl', 'show', unit, '-p', 'MainPID', '--value').strip())
    if pid <= 0:
        raise ValueError('service has no running main process')
    stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return [pid, stat[19], Path('/proc/sys/kernel/random/boot_id').read_text().strip()]

def atomic(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as file:
        json.dump(value, file, sort_keys=True)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)

def nft_layout():
    document = json.loads(run('/usr/local/lib/authority/nft-observe', '-j', 'list', 'table', 'inet', 'authority_tcp'))
    def normalize(value):
        if isinstance(value, list):
            return [normalize(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if key == 'handle':
                    continue
                if key == 'counter' and isinstance(child, dict):
                    child = {k: v for k, v in child.items() if k not in ('packets', 'bytes')}
                if key == 'set' and isinstance(child, dict) and child.get('name') == 'allowed':
                    child = {k: v for k, v in child.items() if k != 'elem'}
                result[key] = normalize(child)
            return result
        return value
    return normalize(document)

def ssh_probe(resources):
    receipt = json.loads(RECEIPT.read_text())
    if receipt['files'] != ssh_files() or receipt['process'] != process('ssh.service'):
        raise ValueError('sshd configuration is not the loaded generation')
    config = dict(line.split(' ', 1) for line in run('/usr/sbin/sshd', '-T', '-C',
        f"user={resources['principal']},host=authority-probe,addr={resources['source']}").splitlines())
    if config['pubkeyauthentication'] != 'yes' or config['authorizedprincipalscommand'] != 'none':
        raise ValueError('unsupported SSH enforcement configuration')
    ca = config['trustedusercakeys']
    principals = config['authorizedprincipalsfile'].replace('%u', resources['principal'])
    if ca not in receipt['files'] or principals not in receipt['files']:
        raise ValueError('SSH trust/principal file not in loaded receipt')
    fingerprints = set()
    for line in Path(ca).read_text().splitlines():
        fields = line.split()
        if fields and not fields[0].startswith('#'):
            key = base64.b64decode(fields[1], validate=True)
            fingerprints.add('SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('='))
    if set(resources['ssh_ca_fingerprints']) != fingerprints:
        raise ValueError('requested CA not trusted by sshd')
    if resources['principal'] not in Path(principals).read_text().splitlines():
        raise ValueError('principal not accepted')
    return receipt

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=2)
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

def mtls_probe(signed):
    challenge = signed['challenge']
    states = []
    for port, unit in [(3004, 'authority-mtls-service.service'), (3005, 'authority-mtls-service-2.service')]:
        before = process(unit)
        path = f'/run/authority-observation/mtls-{port}.sock'
        metadata = os.lstat(path)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not stat.S_ISSOCK(metadata.st_mode):
            raise ValueError('unsafe local enforcement socket')
        connection = UnixHTTPConnection(path)
        try:
            connection.request('GET', '/enforcement')
            response = connection.getresponse()
            data = response.read(8193)
            if response.status != 200 or len(data) > 8192:
                raise ValueError('service observation rejected')
            state = json.loads(data)
        finally:
            connection.close()
        r = challenge['resources']
        if process(unit) != before or state != {'domain_id': challenge['domain_id'], 'target_node_id': challenge['target_node_id'],
            'process_id': before[0], 'mtls_ca_sha256': r['mtls_ca_sha256'], 'service_audience': r['service_audience']}:
            raise ValueError('loaded mTLS state does not match challenge')
        states.append(state)
    return states

def probe(request):
    signed = request['signed']
    resources = signed['challenge']['resources']
    facts = []
    evidence = {}
    errors = []
    def check(name, fn):
        try:
            evidence[name] = fn()
            facts.append(name)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, http.client.HTTPException) as error:
            errors.append(name + ': ' + str(error))
    check('ssh_ca_trusted', lambda: ssh_probe(resources))
    check('mtls_ca_trusted', lambda: mtls_probe(signed))
    def tcp():
        layout = nft_layout()
        if layout != request['nft_layout']:
            raise ValueError('kernel admission layout changed since initialization')
        return layout
    check('tcp_enforcement', tcp)
    def route():
        links = json.loads(run('/usr/sbin/ip', '-j', '-d', 'link', 'show', 'dev', request['interface']))
        if len(links) != 1 or links[0].get('linkinfo', {}).get('info_kind') != 'wireguard':
            raise ValueError('configured interface is not a WireGuard actuator')
        addresses = json.loads(run('/usr/sbin/ip', '-j', 'address', 'show', 'dev', request['interface']))
        if not any('UP' in a['flags'] and any(i.get('local') == resources['target'] for i in a['addr_info']) for a in addresses):
            raise ValueError('target interface/address is not active')
        routes = json.loads(run('/usr/sbin/ip', '-j', 'route', 'get', resources['source'], 'from', resources['target']))
        if len(routes) != 1 or routes[0].get('dev') != request['interface']:
            raise ValueError('concrete route not present')
        return routes
    check('mesh_route_configured', route)
    if 'mesh_route_configured' in facts:
        facts.append('existing_route_configured')
    return {'facts': facts, 'configuration_sha256': digest(evidence), 'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'errors': errors}

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'ssh-before':
        atomic(RECEIPT.with_suffix('.pending'), ssh_files())
        RECEIPT.unlink(missing_ok=True)
    elif mode == 'ssh-after':
        files = ssh_files()
        if files != json.loads(RECEIPT.with_suffix('.pending').read_text()):
            raise ValueError('configuration changed during sshd startup')
        atomic(RECEIPT, {'files': files, 'process': process('ssh.service')})
    elif mode == 'capture-nft':
        print(json.dumps(nft_layout(), sort_keys=True))
    elif mode == 'probe':
        request = json.loads(sys.stdin.buffer.read(65537))
        print(json.dumps(probe(request), sort_keys=True))
    else:
        raise ValueError('unknown probe mode')
