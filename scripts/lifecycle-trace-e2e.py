"""Generated, reproducible traces against real HTTP/DB and kernel adapters.

The live-binding oracle uses Revocation.tla's publish/consume/install/persist/
complete transitions. This is runtime correspondence testing, not refinement proof.
"""
import copy
import json
import os
from pathlib import Path
import random
import subprocess
import time
import urllib.error
import urllib.request

TRACE_TTL_SECONDS = 35
PROBE_TIMEOUT_SECONDS = 0.25


class Model:
    def __init__(self, ports):
        self.ports = ports
        self.published = set()
        self.consumed = set()
        self.tombstones = set()
        self.active = set()
        self.completed = set()

    def install(self, pair):
        assert pair not in self.consumed | self.tombstones
        self.consumed.add(pair)
        self.active.add(pair)

    def publish(self, pair):
        self.published.add(pair)

    def complete(self, pair):
        assert pair in self.published
        self.tombstones.add(pair)
        self.active.discard(pair)
        self.completed.add(pair)
        assert not self.active & self.completed

    def admitted(self, port):
        return any(kind == 'wireguard.peer' for _, kind in self.active) and any(
            kind == 'tcp.port' and port in self.ports[decision]
            for decision, kind in self.active)


def run(issue, revoke, http, wait, allowed, agent, control):
    proxy = os.environ['AUTHORITY_E2E_DELIVERY_PROXY']
    seeds = [int(value, 0) for value in os.environ.get('AUTHORITY_E2E_TRACE_SEEDS', '0,7,42').split(',')]
    assert seeds, 'at least one generated trace is required'
    output = Path(os.environ.get('AUTHORITY_E2E_TRACE_FILE', f'/tmp/authority-lifecycle-traces-{os.getpid()}.json'))
    traces = []

    def get(url):
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.load(response)

    try:
        for seed in seeds:
            rng = random.Random(seed)
            ports = [8080, 8081]
            rng.shuffle(ports)
            scopes = {'transport': set(ports), 'first': {ports[0]},
                      'other': {ports[1]}, 'late': {rng.choice(ports)}}
            model = Model(scopes)
            trace = {'seed': seed, 'scopes': {key: sorted(value) for key, value in scopes.items()}, 'steps': []}
            traces.append(trace)
            http(f'{proxy}/__e2e/delivery', {'blocked': True})
            grants = {name: issue(sorted(scope), ttl=TRACE_TTL_SECONDS, network=name == 'transport')
                      for name, scope in scopes.items()}
            ids = {name: value['decision_id'] for name, value in grants.items()}
            expires = min(value['tcp_grant']['grant']['expires_at'] for value in grants.values())
            notices = {}

            def record(action, name, kind='tcp.port'):
                trace['steps'].append({'action': action, 'decision': name, 'adapter': kind})

            def observe():
                assert time.time() + 0.5 < expires, f'trace {seed} exceeded live-grant window'
                expected = {port: model.admitted(port) for port in ports}
                actual = {port: allowed(2223 if port == 8080 else 2224, timeout=PROBE_TIMEOUT_SECONDS) for port in ports}
                trace['steps'][-1]['expected_ports'] = expected
                trace['steps'][-1]['actual_ports'] = actual
                assert actual == expected, f'seed={seed}, step={len(trace["steps"])-1}, {trace["steps"][-1]}'

            def apply(name, kind='tcp.port', expected=200, error=None):
                envelope = grants[name]['tcp_grant' if kind == 'tcp.port' else 'network_grant']
                route = 'tcp-grants' if kind == 'tcp.port' else 'network-grants'
                response = http(f'{agent}/v1/{route}', envelope, expected)
                if error:
                    assert response['error'] == error
                if expected == 200:
                    model.install((name, kind))
                record('apply' if expected == 200 else error, name, kind)

            def publish(name, kind='tcp.port'):
                notices[name, kind] = revoke(ids[name], [kind])
                model.publish((name, kind))
                record('publish', name, kind)

            def deliver(name, kind='tcp.port'):
                http(f'{agent}/v1/revocations', notices[name, kind])
                model.complete((name, kind))
                record('deliver', name, kind)
                observe()

            apply('transport', 'wireguard.peer')
            subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True,
                           stdout=subprocess.DEVNULL)
            apply('first')
            apply('other')
            wait(lambda: allowed(2223) and allowed(2224))
            observe()
            publication = ['first', 'late']
            rng.shuffle(publication)
            for name in publication:
                publish(name)
                observe()  # Durable publication alone must not mutate the adapter.

            # The real dispatcher must encounter at least one injected failure.
            wait(lambda: all(value['notice']['sequence'] in
                             http(f'{proxy}/__e2e/delivery', {'blocked': True})['rejected_sequences']
                             for value in notices.values()))
            target = grants['first']['tcp_grant']['grant']['target_node_id']
            wanted = {value['notice']['sequence']: value for value in notices.values()}
            found = {}
            cursor = 0
            while True:
                feed = get(f'{control}/v1/revocations?target_node_id={target}&after={cursor}')
                sequences = [value['notice']['sequence'] for value in feed['notices']]
                assert sequences == sorted(set(sequences)) and all(value > cursor for value in sequences)
                for value in feed['notices']:
                    if value['notice']['sequence'] in wanted:
                        found[value['notice']['sequence']] = value
                if not sequences or len(found) == len(wanted):
                    break
                assert feed['next_cursor'] > cursor
                cursor = feed['next_cursor']
            assert found == wanted, 'DB pull feed changed or omitted a committed signed notice'
            # Deliver the newer sequence first, then the older notice: no global
            # watermark may suppress a different decision's revocation.
            for name in reversed(publication):
                deliver(name)
            duplicates = [rng.choice(publication) for _ in range(rng.randint(2, 5))]
            for name in duplicates:
                deliver(name)
            for name in rng.sample(publication, len(publication)):
                apply(name, expected=409, error='tcp_grant_revoked')
                observe()
            apply('other', expected=409, error='tcp_grant_replayed')
            observe()
            apply('transport')  # A new live decision may authorize an overlapping scope.
            observe()
            publish('transport')
            deliver('transport')
            tampered = copy.deepcopy(grants['other']['tcp_grant'])
            tampered['grant']['destination_ports'] = [ports[0]]
            assert http(f'{agent}/v1/tcp-grants', tampered, 401)['error'] == 'invalid_tcp_grant'
            record('tamper', 'other')
            observe()

            # A real receiver restart discards installed authority but retains
            # replay and revocation ledgers. Restore only transport first to
            # distinguish nft cleanup from denial caused by a missing WG peer.
            subprocess.run(['mise', 'run', 'mesh:agent:restart'], check=True,
                           stdout=subprocess.DEVNULL)
            model.active.clear()
            record('receiver-restart', 'transport', 'wireguard.peer')
            def receiver_ready():
                try:
                    return get(f'{agent}/v1/identity').get('node_id') == target
                except (urllib.error.URLError, TimeoutError):
                    return False
            wait(receiver_ready)
            observe()
            recovery = issue([ports[1]], ttl=TRACE_TTL_SECONDS, network=True)
            grants['recovery'] = recovery
            ids['recovery'] = recovery['decision_id']
            scopes['recovery'] = {ports[1]}
            trace['scopes']['recovery'] = [ports[1]]
            apply('recovery', 'wireguard.peer')
            subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True,
                           stdout=subprocess.DEVNULL)
            wait(lambda: subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL).returncode == 0)
            observe()
            apply('transport', 'wireguard.peer', 409, 'network_grant_replayed')
            apply('other', expected=409, error='tcp_grant_replayed')
            apply('first', expected=409, error='tcp_grant_revoked')
            observe()
            apply('recovery')
            observe()

            # Resume automatic delivery after publication. Its retry must remove
            # the last TCP rule without removing the independent WG binding.
            publish('recovery')
            observe()
            wait(lambda: notices['recovery', 'tcp.port']['notice']['sequence'] in
                 http(f'{proxy}/__e2e/delivery', {'blocked': True})['rejected_sequences'])
            before = http(f'{proxy}/__e2e/delivery', {'blocked': False})['forwarded']
            wait(lambda: not allowed(2223) and not allowed(2224))
            model.complete(('recovery', 'tcp.port'))
            record('automatic-retry', 'recovery')
            observe()
            assert http(f'{proxy}/__e2e/delivery', {'blocked': False})['forwarded'] > before
            assert subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode == 0
            # Repeated publication must return the exact original durable notice.
            assert revoke(ids['first'], ['tcp.port']) == notices['first', 'tcp.port']
            publish('recovery', 'wireguard.peer')
            deliver('recovery', 'wireguard.peer')
            assert subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode != 0
            print(f'Lifecycle trace seed={seed}: {len(trace["steps"])} steps matched real HTTP/DB/TCP/WG', flush=True)
    finally:
        try:
            output.write_text(json.dumps(traces, indent=2) + '\n')
            print(f'Lifecycle trace artifact (logical actions only): {output}', flush=True)
        finally:
            http(f'{proxy}/__e2e/delivery', {'blocked': False})
