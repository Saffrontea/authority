"""Replay timed E2E reconstructions through the actual joint WG/TCP TLA+ model."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

from timed_trace import WG_FIELDS, TCP_FIELDS, SET_FIELDS
from tla_replay import LABEL, PORTS, tla_set
from tlc_tools import ROOT, checker

ACTIONS = {'WgApply', 'WgPublish', 'WgPersist', 'WgComplete', 'Expire', 'FailExpire', 'FailRevoke',
           'TcpApply', 'TcpPublish', 'TcpPersist', 'TcpComplete', 'Tick', 'Collect', 'Crash',
           'Recover', 'RejectWgExpired', 'RejectTcpExpired', 'RejectWgRevoked', 'RejectTcpReplay', 'Stutter'}
GLOBAL = {'Tick', 'Collect', 'Crash', 'Recover', 'Stutter'}


def encode_timed_trace(trace):
    if type(trace.get('version')) is not int or trace['version'] != 2 or trace.get('scenario') != 'time-and-command-failures' or trace.get('completed') is not True:
        raise ValueError('requires a completed version 2 timed trace')
    wg, tcp, ports = trace['wg_expiries'], trace['tcp_expiries'], trace['tcp_ports']
    for deadlines in (wg, tcp):
        if not isinstance(deadlines, dict) or not deadlines or any(not LABEL.fullmatch(d) or type(t) is not int or t <= 0 for d, t in deadlines.items()):
            raise ValueError('invalid immutable expiry catalog')
    if set(ports) != set(tcp) or any(not isinstance(ps, list) or not ps or len(set(ps)) != len(ps)
                                   or any(type(p) is not int or p not in PORTS for p in ps) for ps in ports.values()):
        raise ValueError('invalid TCP scopes')
    states, edges, observations = trace['states'], trace['edges'], trace['observations']
    if not states or len(edges) != len(states) - 1 or not observations:
        raise ValueError('incomplete timed history')
    encoded_states = []
    for state in states:
        if set(state) != set(WG_FIELDS + TCP_FIELDS):
            raise ValueError('unexpected timed state fields')
        values = {}
        for field in WG_FIELDS + TCP_FIELDS:
            value = state[field]
            catalog = tcp if field.startswith('tcp') else wg
            if field in SET_FIELDS:
                if not isinstance(value, list) or len(set(value)) != len(value) or any(d not in catalog for d in value):
                    raise ValueError('invalid timed set')
                values[field] = tla_set(map(json.dumps, value))
            elif field in {'ready', 'badCleanup'}:
                if type(value) is not bool:
                    raise ValueError('invalid timed boolean')
                values[field] = str(value).upper()
            elif field == 'now':
                if type(value) is not int or value < 0:
                    raise ValueError('invalid logical time')
                values[field] = str(value)
            else:
                if value is not None and value not in wg:
                    raise ValueError('invalid kernel/registry binding')
                values[field] = 'None' if value is None else json.dumps(value)
        encoded_states.append('<<<<' + ', '.join(values[f] for f in WG_FIELDS) + '>>, <<' + ', '.join(values[f] for f in TCP_FIELDS) + '>>>>')
    encoded_edges = []
    for edge in edges:
        if set(edge) != {'action', 'decision'} or edge['action'] not in ACTIONS:
            raise ValueError('unknown timed edge')
        action, decision = edge['action'], edge['decision']
        catalog = tcp if action.startswith('Tcp') or action.startswith('RejectTcp') else wg
        if action in GLOBAL:
            if decision is not None:
                raise ValueError('global timed action has a binding')
        elif decision not in catalog:
            raise ValueError('unknown timed action binding')
        encoded_edges.append(f'[action |-> {json.dumps(action)}, decision |-> {json.dumps(decision or "")}]')
    encoded_obs = []
    has_peer = False
    for observation in observations:
        if set(observation) != {'state_index', 'ports', 'peer'}:
            raise ValueError('unknown timed observation fields')
        index, actual, peer = observation['state_index'], observation['ports'], observation['peer']
        if type(index) is not int or not 1 <= index <= len(states) or len(actual) != 2 or set(map(str, actual)) != {'8080', '8081'} or any(type(v) is not bool for v in actual.values()):
            raise ValueError('invalid timed port observation')
        if peer is not None and type(peer) is not bool:
            raise ValueError('invalid peer observation')
        has_peer |= peer is not None
        admitted = tla_set(str(p) for p, value in actual.items() if value)
        encoded_obs.append(f'[state |-> {index}, admitted |-> {admitted}, peerMeasured |-> {str(peer is not None).upper()}, peer |-> {str(bool(peer)).upper()}]')
    if not has_peer:
        raise ValueError('timed replay requires actual kernel peer observations')
    def function(catalog, encode):
        return '[d \\in ' + tla_set(map(json.dumps, catalog)) + ' |-> CASE ' + ' [] '.join(
            f'd = {json.dumps(d)} -> {encode(value)}' for d, value in catalog.items()) + ']'
    module = r'''--------------------------- MODULE TimedReplay ---------------------------
EXTENDS TimedAdmission, Sequences
VARIABLE step
Recorded == @STATES@
Edges == @EDGES@
Observations == @OBS@
RecordedExpiries == @WG@
RecordedTcpExpiries == @TCP@
RecordedTcpPorts == @PORTS@
ObservedPortsMatch == \A o \in Observations:
                       o.state = step => o.admitted = {p \in {8080, 8081}: Admitted(p)}
ObservedPeerMatches == \A o \in Observations:
                        (o.state = step /\ o.peerMeasured) => o.peer = (kernel # None)
Declared(e) == CASE e.action = "WgApply" -> PeerOnly(Apply(e.decision))
               [] e.action = "WgPublish" -> PeerOnly(Publish(e.decision))
               [] e.action = "WgPersist" -> PeerOnly(Persist(e.decision))
               [] e.action = "WgComplete" -> PeerOnly(Complete(e.decision))
               [] e.action = "Expire" -> PeerOnly(Expire(e.decision))
               [] e.action = "FailExpire" -> PeerOnly(FailExpire(e.decision))
               [] e.action = "FailRevoke" -> ready /\ e.decision \in tombstones /\ registry = e.decision /\ UNCHANGED joint
               [] e.action = "TcpApply" -> TcpApply(e.decision)
               [] e.action = "TcpPublish" -> TcpPublish(e.decision)
               [] e.action = "TcpPersist" -> TcpPersist(e.decision)
               [] e.action = "TcpComplete" -> TcpComplete(e.decision)
               [] e.action = "Tick" -> TimeStep
               [] e.action = "Collect" -> Collect
               [] e.action = "Crash" -> PeerOnly(Crash)
               [] e.action = "Recover" -> Recover
               [] e.action = "RejectWgExpired" -> ready /\ ~Live(e.decision) /\ UNCHANGED joint
               [] e.action = "RejectTcpExpired" -> ready /\ ~TcpLive(e.decision) /\ UNCHANGED joint
               [] e.action = "RejectWgRevoked" -> ready /\ Live(e.decision) /\ e.decision \in tombstones /\ UNCHANGED joint
               [] e.action = "RejectTcpReplay" -> ready /\ TcpLive(e.decision) /\ e.decision \in tcpConsumed /\ e.decision \notin tcpTombstones /\ UNCHANGED joint
               [] e.action = "Stutter" -> UNCHANGED joint
InitReplay == /\ InitTimed /\ step = 1 /\ joint = Recorded[1]
NextReplay == \/ /\ step < Len(Recorded)
                  /\ (NextTimed \/ UNCHANGED joint)
                  /\ Declared(Edges[step])
                  /\ joint' = Recorded[step + 1] /\ step' = step + 1
              \/ /\ step = Len(Recorded) /\ UNCHANGED <<joint, step>>
SpecReplay == InitReplay /\ [][NextReplay]_<<joint, step>> /\ WF_<<joint, step>>(NextReplay)
=============================================================================
'''
    for token, value in {'@STATES@': '<<' + ',\n'.join(encoded_states) + '>>', '@EDGES@': '<<' + ', '.join(encoded_edges) + '>>',
                         '@OBS@': tla_set(encoded_obs), '@WG@': function(wg, str), '@TCP@': function(tcp, str),
                         '@PORTS@': function(ports, lambda ps: tla_set(map(str, ps)))}.items():
        module = module.replace(token, value)
    maximum = max(*wg.values(), *tcp.values(), *(s['now'] for s in states))
    config = ('CONSTANTS\n Decisions = ' + tla_set(map(json.dumps, wg)) + '\n TcpDecisions = ' + tla_set(map(json.dumps, tcp)) +
              '\n None = noPeer\n Early = ' + json.dumps(next(iter(wg))) + '\n LateDeadline = 3\n MaxTime = ' + str(maximum) +
              '\n Expiries <- RecordedExpiries\n TcpExpiries <- RecordedTcpExpiries\n TcpPorts <- RecordedTcpPorts\n'
              'SPECIFICATION SpecReplay\nCHECK_DEADLOCK TRUE\n'
              'INVARIANTS TypeTimed RegistryTracksKernel NoCrossDecisionCleanup NoResurrection DurableWhileLive NoExpiredTcp NoTcpResurrection TcpDurableWhileLive TcpAuthenticatedRevocations ObservedPortsMatch ObservedPeerMatches\n')
    return module, config


def verify_timed_trace(trace, expected_failure=None):
    module, config = encode_timed_trace(trace)
    java, jar = checker()
    dependencies = {name: (ROOT / f'formal/tla/{name}.tla').read_text()
                    for name in ('PeerLifecycle', 'TimedAdmission')}
    views = {'PeerLifecycle': 'vars==<<' + ','.join(WG_FIELDS) + '>>',
             'TimedAdmission': 'tcpvars==<<' + ','.join(TCP_FIELDS) + '>>'}
    for name, view in views.items():
        if view not in re.sub(r'\s+', '', dependencies[name]):
            raise ValueError('timed model variable view changed')
    with tempfile.TemporaryDirectory(prefix='authority-timed-replay-') as directory:
        directory = Path(directory)
        for name, source in dependencies.items():
            (directory / f'{name}.tla').write_text(source)
        (directory / 'TimedReplay.tla').write_text(module)
        (directory / 'TimedReplay.cfg').write_text(config)
        result = subprocess.run([java, '-XX:+UseParallelGC', f'-Djava.io.tmpdir={directory}', '-jar', str(jar), '-workers', '1', '-metadir', str(directory / 'states'), 'TimedReplay.tla'],
                                cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if expected_failure:
        if result.returncode == 0 or expected_failure not in result.stdout:
            raise AssertionError('timed trace mutation did not fail as expected:\n' + result.stdout)
    else:
        count = re.search(r'(\d+) distinct states found', result.stdout)
        if result.returncode or 'Model checking completed. No error has been found.' not in result.stdout or not count or int(count[1]) != len(trace['states']):
            raise AssertionError('TLC timed trace replay failed:\n' + result.stdout)
        print(f'TLC timed trace seed={trace["seed"]}: {len(trace["states"])} states and {len(trace["observations"])} actual observations verified', flush=True)
