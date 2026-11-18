"""Check reconstructed live E2E states and measured port admission with actual TLC."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

from tlc_tools import ROOT, checker

FIELDS = ('published', 'tombstones', 'active', 'consumed', 'acknowledged', 'completed')
ADAPTERS = {'tcp.port', 'wireguard.peer'}
PORTS = {8080, 8081}
LABEL = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')


def tla_set(values):
    return '{' + ', '.join(values) + '}'


def encode_trace(trace):
    if type(trace.get('version')) is not int or trace['version'] != 1 or trace.get('scenario') != 'live' or trace.get('completed') is not True:
        raise ValueError('requires a completed version 1 live trace; other lifecycle scenarios are not supported')
    scopes = trace['scopes']
    if not scopes or any(not isinstance(name, str) or not LABEL.fullmatch(name) for name in scopes):
        raise ValueError('invalid decision labels')
    if any(not isinstance(ports, list) or len(set(ports)) != len(ports)
           or not ports or any(type(port) is not int or port not in PORTS for port in ports)
           for ports in scopes.values()):
        raise ValueError('invalid requested service scopes')
    states = trace['states']
    if not isinstance(states, list) or not states:
        raise ValueError('missing state history')
    tuples = []
    for state in states:
        if set(state) != set(FIELDS):
            raise ValueError('unexpected state fields')
        fields = []
        for key in FIELDS:
            pairs = state[key]
            if not isinstance(pairs, list) or any(not isinstance(pair, list) or len(pair) != 2
                or pair[0] not in scopes or pair[1] not in ADAPTERS for pair in pairs):
                raise ValueError('invalid decision/adapter pair')
            if len({tuple(pair) for pair in pairs}) != len(pairs):
                raise ValueError('duplicate pair in state')
            fields.append(tla_set(f'<<{json.dumps(name)}, {json.dumps(kind)}>>' for name, kind in pairs))
        tuples.append('<<' + ', '.join(fields) + '>>')
    edges = trace['edges']
    if not isinstance(edges, list) or len(edges) != len(states) - 1:
        raise ValueError('one declared action is required per transition')
    encoded_edges = []
    for edge in edges:
        if set(edge) != {'action', 'pair'}:
            raise ValueError('unexpected edge fields')
        action, pair = edge['action'], edge['pair']
        if action not in {'Consume', 'Install', 'Publish', 'Persist', 'Complete', 'ReceiverRestart', 'Stutter'}:
            raise ValueError('unsupported declared action')
        if pair is None:
            if action not in {'Stutter', 'ReceiverRestart'}:
                raise ValueError('action requires a binding')
            encoded_pair = '<<"", "">>'
        elif not isinstance(pair, list) or len(pair) != 2 or pair[0] not in scopes or pair[1] not in ADAPTERS:
            raise ValueError('invalid action binding')
        else:
            encoded_pair = f'<<{json.dumps(pair[0])}, {json.dumps(pair[1])}>>'
        encoded_edges.append(f'[action |-> {json.dumps(action)}, pair |-> {encoded_pair}]')
    observations = trace['observations']
    if not isinstance(observations, list) or not observations:
        raise ValueError('missing actual port observations')
    encoded_observations = []
    for observation in observations:
        if set(observation) != {'state_index', 'ports'}:
            raise ValueError('unexpected observation fields')
        index, ports = observation['state_index'], observation['ports']
        if type(index) is not int or not 1 <= index <= len(states):
            raise ValueError('invalid observation state index')
        # In-memory traces have integer keys; JSON artifacts have string keys.
        if not isinstance(ports, dict) or set(map(str, ports)) != set(map(str, PORTS)) or len(ports) != len(PORTS):
            raise ValueError('an observation must measure both managed ports')
        if any(type(value) is not bool for value in ports.values()):
            raise ValueError('invalid actual port observation')
        admitted = tla_set(str(port) for port, value in ports.items() if value)
        encoded_observations.append(f'[state |-> {index}, admitted |-> {admitted}]')
    scope_function = '[d \\in Decisions |-> CASE ' + ' [] '.join(
        f'd = {json.dumps(name)} -> {tla_set(map(str, ports))}' for name, ports in scopes.items()) + ']'
    module = r'''--------------------------- MODULE TraceReplay ---------------------------
EXTENDS Revocation, Naturals, Sequences
VARIABLE step
Recorded == @STATES@
Observations == @OBSERVATIONS@
Edges == @EDGES@
ScopePorts == @SCOPES@
ManagedPorts == {8080, 8081}
Admitted(port) == /\ \E p \in active: p[2] = "wireguard.peer"
                  /\ \E p \in active: p[2] = "tcp.port" /\ port \in ScopePorts[p[1]]
ObservedPortsMatch == \A o \in Observations:
                       o.state = step => o.admitted = {p \in ManagedPorts: Admitted(p)}
DeclaredAction(e) == CASE e.action = "Consume" -> Consume(e.pair)
                      [] e.action = "Install" -> Install(e.pair)
                      [] e.action = "Publish" -> Publish(e.pair)
                      [] e.action = "Persist" -> Persist(e.pair)
                      [] e.action = "Complete" -> Complete(e.pair)
                      [] e.action = "ReceiverRestart" -> ReceiverRestart
                      [] e.action = "Stutter" -> UNCHANGED vars
InitReplay == /\ Init /\ step = 1 /\ vars = Recorded[1]
NextReplay == \/ /\ step < Len(Recorded)
                  /\ (Next \/ UNCHANGED vars)
                  /\ DeclaredAction(Edges[step])
                  /\ vars' = Recorded[step + 1]
                  /\ step' = step + 1
              \/ /\ step = Len(Recorded) /\ UNCHANGED <<vars, step>>
SpecReplay == InitReplay /\ [][NextReplay]_<<vars, step>>
              /\ WF_<<vars, step>>(NextReplay)
=============================================================================
'''.replace('@STATES@', '<<' + ',\n'.join(tuples) + '>>').replace(
        '@OBSERVATIONS@', tla_set(encoded_observations)).replace('@SCOPES@', scope_function).replace(
        '@EDGES@', '<<' + ', '.join(encoded_edges) + '>>')
    config = ('CONSTANTS\n Decisions = ' + tla_set(map(json.dumps, scopes)) +
              '\n Adapters = ' + tla_set(map(json.dumps, sorted(ADAPTERS))) +
              '\nSPECIFICATION SpecReplay\nCHECK_DEADLOCK TRUE\n'
              'INVARIANTS TypeOK DurableBeforeAck NoResurrection AuthenticatedRevocations InstalledWasConsumed ObservedPortsMatch\n'
              'PROPERTY EventuallyRevoked\n')
    return module, config


def verify_live_trace(trace, expected_failure=None):
    module, config = encode_trace(trace)
    java, jar = checker()
    source = (ROOT / 'formal/tla/Revocation.tla').read_text()
    # The serializer has an explicit tuple view; schema drift must fail closed.
    if 'vars == <<published, tombstones, active, consumed, acknowledged, completed>>' not in source:
        raise ValueError('revocation variable view changed')
    with tempfile.TemporaryDirectory(prefix='authority-replay-') as path:
        path = Path(path)
        (path / 'Revocation.tla').write_text(source)
        (path / 'TraceReplay.tla').write_text(module)
        (path / 'TraceReplay.cfg').write_text(config)
        result = subprocess.run([java, '-XX:+UseParallelGC', '-jar', str(jar), '-workers', '1',
                                 '-metadir', str(path / 'states'), 'TraceReplay.tla'],
                                cwd=path, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=120)
    if expected_failure:
        if result.returncode == 0 or expected_failure not in result.stdout:
            raise AssertionError('trace mutation did not fail as expected:\n' + result.stdout)
    else:
        count = re.search(r'(\d+) distinct states found', result.stdout)
        if result.returncode != 0 or 'Model checking completed. No error has been found.' not in result.stdout or not count or int(count[1]) != len(trace['states']):
            raise AssertionError('TLC live trace replay failed:\n' + result.stdout)
        print(f'TLC live trace seed={trace["seed"]}: {len(trace["states"])} states and {len(trace["observations"])} actual port observations verified', flush=True)
