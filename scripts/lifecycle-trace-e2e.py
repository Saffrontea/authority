"""Generated, reproducible traces against real HTTP/DB and kernel adapters.

The live-binding oracle uses Revocation.tla's publish/consume/install/persist/
complete transitions. Live snapshots and measured port admission are replayed
through TLC, as are timed WG/TCP snapshots and measured peer presence. This is
correspondence testing, not a universal refinement proof.
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

from tla_replay import verify_live_trace
from timed_trace import TimedTrace
from timed_tla_replay import verify_timed_trace

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
        self.history = []
        self.edges = []
        self.snapshot()

    def snapshot(self, action=None, pair=None):
        if action is not None:
            self.edges.append({'action': action, 'pair': list(pair) if pair else None})
        self.history.append({key: [list(pair) for pair in sorted(value)] for key, value in {
            'published': self.published, 'tombstones': self.tombstones,
            'active': self.active, 'consumed': self.consumed,
            'acknowledged': self.completed, 'completed': self.completed,
        }.items()})

    def receiver_restart(self):
        had_active = bool(self.active)
        self.active.clear()
        self.snapshot('ReceiverRestart' if had_active else 'Stutter')

    def install(self, pair):
        assert pair not in self.consumed | self.tombstones
        self.consumed.add(pair)
        self.snapshot('Consume', pair)
        if pair[1] == 'wireguard.peer':
            self.active = {current for current in self.active if current[1] != 'wireguard.peer'}
        self.active.add(pair)
        self.snapshot('Install', pair)

    def publish(self, pair):
        already = pair in self.published
        self.published.add(pair)
        self.snapshot('Stutter' if already else 'Publish', pair)

    def complete(self, pair):
        assert pair in self.published
        persisted = pair in self.tombstones
        self.tombstones.add(pair)
        self.snapshot('Stutter' if persisted else 'Persist', pair)
        completed = pair in self.completed
        self.active.discard(pair)
        self.completed.add(pair)
        assert not self.active & self.completed
        self.snapshot('Stutter' if completed else 'Complete', pair)

    def admitted(self, port):
        return any(kind == 'wireguard.peer' for _, kind in self.active) and any(
            kind == 'tcp.port' and port in self.ports[decision]
            for decision, kind in self.active)


def run(issue, revoke, http, wait, allowed, agent, control, probe, pull):
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
            trace = {'seed': seed, 'scenario': 'live', 'version': 1, 'completed': False,
                     'scopes': {key: sorted(value) for key, value in scopes.items()},
                     'states': model.history, 'edges': model.edges, 'observations': [], 'steps': []}
            traces.append(trace)
            http(f'{proxy}/__e2e/delivery', {'blocked': True})
            grants = {name: issue(sorted(scope), ttl=TRACE_TTL_SECONDS, network=name == 'transport')
                      for name, scope in scopes.items()}
            ids = {name: value['decision_id'] for name, value in grants.items()}
            expires = min(value['tcp_grant']['grant']['expires_at'] for value in grants.values())
            notices = {}

            def record(action, name, kind='tcp.port'):
                trace['steps'].append({'action': action, 'decision': name, 'adapter': kind,
                                       'state_index': len(model.history)})

            def observe():
                assert time.time() + 0.5 < expires, f'trace {seed} exceeded live-grant window'
                expected = {port: model.admitted(port) for port in ports}
                details = {port: probe(2223 if port == 8080 else 2224, timeout=PROBE_TIMEOUT_SECONDS) for port in ports}
                actual = {port: value['admitted'] for port, value in details.items()}
                trace['steps'][-1]['probe_details'] = details
                trace['steps'][-1]['expected_ports'] = expected
                trace['steps'][-1]['actual_ports'] = actual
                trace['observations'].append({'state_index': len(model.history), 'ports': actual})
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
                feed = pull(target, cursor)
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
            restart_task = 'mesh:test:crash' if seed % 2 else 'mesh:agent:restart'
            subprocess.run(['mise', 'run', restart_task], check=True,
                           stdout=subprocess.DEVNULL)
            model.receiver_restart()
            record('receiver-crash' if seed % 2 else 'receiver-restart', 'transport', 'wireguard.peer')
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
            trace['completed'] = True
            verify_live_trace(trace)
            print(f'Lifecycle trace seed={seed}: {len(trace["steps"])} steps matched real HTTP/DB/TCP/WG', flush=True)
            run_timed_fault_trace(seed, traces, issue, revoke, http, wait, allowed, agent, proxy, probe)
    finally:
        try:
            output.write_text(json.dumps(traces, indent=2) + '\n')
            print(f'Lifecycle trace artifact (logical actions only): {output}', flush=True)
        finally:
            http(f'{proxy}/__e2e/delivery', {'blocked': False})


def run_timed_fault_trace(seed, traces, issue, revoke, http, wait, allowed, agent, proxy, probe):
    """Compose live revocation transitions with PeerLifecycle expiry/replacement.

    TCP timeouts remove rules in the kernel. WG expiry is a pending cleanup until
    its command succeeds; a failed timer retains the current binding for retry.
    """
    rng = random.Random(seed ^ 0xA17E)
    port = rng.choice([8080, 8081])
    other_port = 8081 if port == 8080 else 8080
    model = Model({})
    grants = {}
    deadlines = {}
    trace = {'seed': seed, 'scenario': 'time-and-command-failures', 'scopes': {}, 'steps': []}
    traces.append(trace)
    started = time.monotonic()
    shadow = TimedTrace(trace)
    fault_active = False

    def task(name, check=True):
        nonlocal fault_active
        result = subprocess.run(['mise', 'run', f'mesh:test:{name}'], check=check,
                                stdout=subprocess.DEVNULL, stderr=None if check else subprocess.DEVNULL)
        if result.returncode == 0 and name in {'wg-fail', 'wg-restore'}:
            fault_active = name == 'wg-fail'
        return result

    def record(action, name, kind='wireguard.peer'):
        trace['steps'].append({'action': action, 'decision': name, 'adapter': kind,
                               'elapsed_seconds': round(time.monotonic() - started, 3),
                               'state_index': len(trace['states'])})

    def issue_named(name, ports, ttl, network=False):
        value = issue(ports, ttl=ttl, network=network)
        grants[name] = value
        model.ports[name] = set(ports)
        trace['scopes'][name] = {'ports': ports, 'tcp_ttl_seconds': ttl}
        if 'network_grant' in value:
            network = value['network_grant']['grant']
            trace['scopes'][name]['network_ttl_seconds'] = network['expires_at'] - network['not_before']
        for key, kind in [('tcp_grant', 'tcp.port'), ('network_grant', 'wireguard.peer')]:
            if key in value:
                deadlines[name, kind] = value[key]['grant']['expires_at']
        shadow.register(name, value, ports)
        return value

    def apply(name, kind='wireguard.peer', status=200, error=None):
        key, route = ('tcp_grant', 'tcp-grants') if kind == 'tcp.port' else ('network_grant', 'network-grants')
        result = http(f'{agent}/v1/{route}', grants[name][key], status)
        if error:
            assert result['error'] == error
        if status == 200:
            model.install((name, kind))
            shadow.action('TcpApply' if kind == 'tcp.port' else 'WgApply', name)
        else:
            shadow.action({'invalid_network_grant': 'RejectWgExpired', 'invalid_tcp_grant': 'RejectTcpExpired',
                           'network_grant_revoked': 'RejectWgRevoked', 'tcp_grant_replayed': 'RejectTcpReplay'}[error], name)
        record('apply' if status == 200 else error, name, kind)

    def peer_present():
        result = subprocess.run(['mise', 'run', 'mesh:test:peer-present'], check=True,
                                capture_output=True, text=True)
        values = [line.split('=', 1)[1] for line in result.stdout.splitlines()
                  if line.startswith('authority-e2e-peer=')]
        assert len(values) == 1 and values[0] in {'present', 'absent'}, result.stdout
        return values[0] == 'present'

    def observe():
        shadow.advance()
        now = time.time()
        # Time alone expires TCP authority; WG removal requires successful cleanup.
        model.active = {pair for pair in model.active
                        if pair[1] != 'tcp.port' or deadlines[pair] > now}
        expected = {value: model.admitted(value) for value in (8080, 8081)}
        details = {value: probe(2223 if value == 8080 else 2224, timeout=PROBE_TIMEOUT_SECONDS)
                   for value in (8080, 8081)}
        actual = {value: result['admitted'] for value, result in details.items()}
        trace['steps'][-1]['probe_details'] = details
        trace['steps'][-1].update(expected_ports=expected, actual_ports=actual)
        shadow.observe(actual, None if fault_active else peer_present())
        assert actual == expected, f'seed={seed}, timed step={len(trace["steps"])-1}, {trace["steps"][-1]}'

    def after_expiry(pair, margin=0.3):
        while time.time() < deadlines[pair] + margin:
            time.sleep(max(0, min(0.2, deadlines[pair] + margin - time.time())))

    http(f'{proxy}/__e2e/delivery', {'blocked': True})
    try:
        lease = issue_named('lease', [port], TRACE_TTL_SECONDS, True)
        # A failed kernel install must leave this exact signed grant retryable.
        task('wg-fail')
        try:
            failed = http(f'{agent}/v1/network-grants', lease['network_grant'], 500)
            assert failed['error'] == 'internal_error'
        finally:
            task('wg-restore')
        apply('lease')
        subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
        task('nft-fail')
        try:
            failed = http(f'{agent}/v1/tcp-grants', lease['tcp_grant'], 500)
            assert failed['error'] == 'internal_error'
        finally:
            task('nft-restore')
        apply('lease', 'tcp.port')
        wait(lambda: allowed(2223 if port == 8080 else 2224))
        observe()

        # A real command-spawn error must not ACK or forget the installed peer.
        task('wg-fail')
        try:
            notice = revoke(lease['decision_id'], ['wireguard.peer'])
            model.publish(('lease', 'wireguard.peer'))
            shadow.action('WgPublish', 'lease')
            result = http(f'{agent}/v1/revocations', notice, 500)
            assert result['error'] == 'internal_error'
            model.tombstones.add(('lease', 'wireguard.peer'))
            shadow.action('WgPersist', 'lease')
            shadow.action('FailRevoke', 'lease')
            record('failed-cleanup-no-ack', 'lease')
            assert time.time() + 1 < deadlines['lease', 'tcp.port']
            observe()  # Existing peer and independent TCP scope remain installed.
            apply('lease', status=409, error='network_grant_revoked')
        finally:
            task('wg-restore')
        response = http(f'{agent}/v1/revocations', notice)
        assert response['peer_removed'], 'failed cleanup lost the peer registry entry'
        model.complete(('lease', 'wireguard.peer'))
        shadow.action('WgComplete', 'lease')
        record('retry-cleanup', 'lease')
        observe()
        assert not peer_present()

        # Restore only transport: the independent TCP lease must still work.
        issue_named('carry', [port], TRACE_TTL_SECONDS, True)
        apply('carry')
        subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
        wait(lambda: allowed(2223 if port == 8080 else 2224))
        observe()
        issue_named('short-tcp', [other_port], rng.randint(2, 3))
        apply('short-tcp', 'tcp.port')
        observe()
        after_expiry(('short-tcp', 'tcp.port'))
        record('tcp-timeout', 'short-tcp', 'tcp.port')
        observe()
        apply('short-tcp', 'tcp.port', 401, 'invalid_tcp_grant')

        # Let the actual timer fail with an expired peer still installed, then
        # recover the executable and require its retry to remove the same peer.
        issue_named('timer', [port], rng.randint(2, 3), True)
        apply('timer')
        task('wg-fail')
        try:
            after_expiry(('timer', 'wireguard.peer'))
            wait(lambda: task('wg-expiry-observed', check=False).returncode == 0)
            shadow.action('FailExpire', 'timer')
            record('timer-command-failed', 'timer')
            # WG uses the independently configured server TTL. Keep fresh TCP
            # authority so traffic proves the expired peer is still installed.
            issue_named('during-failure', [port], TRACE_TTL_SECONDS)
            apply('during-failure', 'tcp.port')
            observe()
            apply('timer', status=401, error='invalid_network_grant')
        finally:
            task('wg-restore')
        wait(lambda: not peer_present())
        model.active.discard(('timer', 'wireguard.peer'))
        shadow.action('Expire', 'timer')
        record('timer-retry', 'timer')
        observe()

        old_ttl = rng.randint(2, 3)
        issue_named('old-peer', [port], old_ttl, True)
        apply('old-peer')
        # The API intentionally gives WG its independent server TTL; TCP's
        # requested TTL must not be mistaken for a peer expiry override.
        separation = rng.randint(4, 5)
        time.sleep(separation)
        issue_named('new-peer', [port], old_ttl + rng.randint(5, 6), True)
        assert deadlines['new-peer', 'wireguard.peer'] - deadlines['old-peer', 'wireguard.peer'] >= separation
        apply('new-peer')
        subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
        wait(peer_present)
        after_expiry(('old-peer', 'wireguard.peer'), 1.3)
        # Earlier TCP leases may have expired during the independent WG TTL.
        issue_named('during-replacement', [port], TRACE_TTL_SECONDS)
        apply('during-replacement', 'tcp.port')
        shadow.action('Expire', 'old-peer')
        record('stale-timer', 'old-peer')
        observe()
        assert time.time() + 0.5 < deadlines['new-peer', 'wireguard.peer']
        assert peer_present(), 'old expiry removed a replacement decision'
        after_expiry(('new-peer', 'wireguard.peer'), 0.8)
        wait(lambda: not peer_present())
        model.active.discard(('new-peer', 'wireguard.peer'))
        shadow.action('Expire', 'new-peer')
        record('current-timer', 'new-peer')
        observe()

        # Unclean process death reloads/compacts expired durable records. A dead
        # signed grant must remain invalid even after its replay record is gone.
        shadow.action('Crash')
        task('crash')
        model.active.clear()
        record('crash-after-expiry', 'new-peer')
        def ready():
            try:
                with urllib.request.urlopen(f'{agent}/v1/identity', timeout=2):
                    return True
            except (urllib.error.URLError, TimeoutError):
                return False
        wait(ready)
        task('ledgers-compacted')
        shadow.action('Collect')
        shadow.action('Recover')
        record('expired-ledgers-compacted', 'new-peer')
        for name in ('old-peer', 'new-peer', 'timer'):
            apply(name, status=401, error='invalid_network_grant')
        apply('short-tcp', 'tcp.port', 401, 'invalid_tcp_grant')
        assert time.time() + 1 < deadlines['during-replacement', 'tcp.port']
        apply('during-replacement', 'tcp.port', 409, 'tcp_grant_replayed')
        observe()
        # A valid fresh signature still works after reopening/compaction; an
        # unavailable or misconfigured verifier cannot explain the expired denials.
        fresh = issue_named('post-gc', [port], TRACE_TTL_SECONDS, True)
        apply('post-gc')
        apply('post-gc', 'tcp.port')
        subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
        wait(lambda: allowed(2223 if port == 8080 else 2224))
        observe()
        cleanup = revoke(fresh['decision_id'], ['wireguard.peer', 'tcp.port'])
        shadow.action('WgPublish', 'post-gc')
        shadow.action('TcpPublish', 'post-gc')
        http(f'{agent}/v1/revocations', cleanup)
        shadow.action('WgPersist', 'post-gc')
        shadow.action('TcpPersist', 'post-gc')
        shadow.action('TcpComplete', 'post-gc')
        shadow.action('WgComplete', 'post-gc')
        for kind in ('tcp.port', 'wireguard.peer'):
            model.publish(('post-gc', kind))
            model.complete(('post-gc', kind))
            record('cleanup', 'post-gc', kind)
        observe()
        assert not peer_present()
        trace['completed'] = True
        verify_timed_trace(trace)
        print(f'Timed lifecycle trace seed={seed}: {len(trace["steps"])} steps matched expiry, crash and WG command failures', flush=True)
    finally:
        task('wg-restore')
        http(f'{proxy}/__e2e/delivery', {'blocked': False})
