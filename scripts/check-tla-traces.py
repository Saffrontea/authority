#!/usr/bin/env python3
"""Replay completed live and timed E2E trace artifacts against the checked TLA+ model."""
import argparse
import copy
import json
from pathlib import Path

from tla_replay import encode_trace, verify_live_trace
from tlc_tools import checker
from timed_tla_replay import encode_timed_trace, verify_timed_trace


def fixture():
    # Explicit states, independent of the E2E Python model implementation.
    fields = ('published', 'tombstones', 'active', 'consumed', 'acknowledged', 'completed')
    states = [{field: [] for field in fields}]
    edges = []
    def update(action, pair, **values):
        state = copy.deepcopy(states[-1])
        state.update(values)
        states.append(state)
        edges.append({'action': action, 'pair': pair})
    wg, tcp = ['transport', 'wireguard.peer'], ['first', 'tcp.port']
    update('Consume', wg, consumed=[wg])
    update('Install', wg, active=[wg])
    update('Consume', tcp, consumed=[wg, tcp])
    update('Install', tcp, active=[wg, tcp])
    update('Publish', tcp, published=[tcp])
    update('Persist', tcp, tombstones=[tcp])
    update('Complete', tcp, active=[wg], acknowledged=[tcp], completed=[tcp])
    update('ReceiverRestart', None, active=[])
    return {'version': 1, 'scenario': 'live', 'completed': True, 'seed': 'fixture',
            'scopes': {'transport': [8080], 'first': [8080]}, 'states': states, 'edges': edges,
            'observations': [{'state_index': 5, 'ports': {'8080': True, '8081': False}},
                             {'state_index': 8, 'ports': {'8080': False, '8081': False}},
                             {'state_index': 9, 'ports': {'8080': False, '8081': False}}]}


def self_test():
    trace = fixture()
    verify_live_trace(trace)
    changed = copy.deepcopy(trace)
    changed['observations'][0]['ports']['8081'] = True
    verify_live_trace(changed, 'Invariant ObservedPortsMatch is violated')
    changed = copy.deepcopy(trace)
    changed['states'][1]['consumed'] = []
    verify_live_trace(changed, 'Deadlock reached')
    changed = copy.deepcopy(trace)
    changed['states'][-1]['active'] = [['transport', 'wireguard.peer']]
    verify_live_trace(changed, 'Deadlock reached')
    for mutate in (lambda value: value.update(completed=False),
                   lambda value: value.update(version=True),
                   lambda value: value.update(scenario='time-and-command-failures'),
                   lambda value: value['edges'][0].update(action='UnknownAction'),
                   lambda value: value['states'][0].update(unmodeled=[]),
                   lambda value: value['observations'][0]['ports'].pop('8081')):
        changed = copy.deepcopy(trace)
        mutate(changed)
        try:
            encode_trace(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('unsupported/incomplete trace was accepted')
    print('Trace replay: 3 semantic counterexamples and 6 fail-closed schema cases checked')


def timed_fixture():
    from timed_trace import SET_FIELDS
    state = {'now': 0, 'ready': True, 'kernel': None, 'registry': None, 'badCleanup': False,
             **{key: [] for key in SET_FIELDS}}
    trace = {'version': 2, 'scenario': 'time-and-command-failures', 'completed': True, 'seed': 'fixture',
             'wg_expiries': {'a': 2, 'b': 3, 'c': 10}, 'tcp_expiries': {'a': 3, 'c': 4},
             'tcp_ports': {'a': [8080], 'c': [8081]}, 'states': [copy.deepcopy(state)], 'edges': [], 'observations': []}
    def update(action, decision=None, **values):
        state.update(values)
        trace['states'].append(copy.deepcopy(state))
        trace['edges'].append({'action': action, 'decision': decision})
    def observe(admitted, peer):
        trace['observations'].append({'state_index': len(trace['states']),
                                     'ports': {str(p): p in admitted for p in (8080, 8081)}, 'peer': peer})
    update('WgApply', 'a', consumed=['a'], kernel='a', registry='a', timers=['a'])
    update('TcpApply', 'a', tcpConsumed=['a'], tcpActive=['a'])
    observe({8080}, True)
    update('WgApply', 'b', consumed=['a', 'b'], kernel='b', registry='b', timers=['a', 'b'])
    update('Tick', now=1)
    update('Tick', now=2)
    update('Expire', 'a', timers=['b'])
    observe({8080}, True)
    update('Tick', now=3, tcpActive=[])
    update('FailExpire', 'b')
    observe(set(), True)
    update('Expire', 'b', kernel=None, registry=None, timers=[])
    observe(set(), False)
    update('Crash', ready=False)
    update('Collect', consumed=[], tcpConsumed=[])
    update('Recover', ready=True)
    update('RejectWgExpired', 'a')
    update('WgApply', 'c', consumed=['c'], kernel='c', registry='c', timers=['c'])
    update('TcpApply', 'c', tcpConsumed=['c'], tcpActive=['c'])
    update('RejectTcpReplay', 'c')
    observe({8081}, True)
    update('WgPublish', 'c', published=['c'])
    update('WgPersist', 'c', tombstones=['c'])
    update('FailRevoke', 'c')
    observe({8081}, True)
    update('WgComplete', 'c', completed=['c'], kernel=None, registry=None)
    observe(set(), False)
    update('TcpPublish', 'c', tcpPublished=['c'])
    update('TcpPersist', 'c', tcpTombstones=['c'])
    update('TcpComplete', 'c', tcpCompleted=['c'], tcpActive=[])
    observe(set(), False)
    update('Tick', now=4)
    update('Collect', tcpConsumed=[])
    observe(set(), False)
    return trace


def self_test_timed():
    trace = timed_fixture()
    verify_timed_trace(trace)
    changed = copy.deepcopy(trace)
    changed['observations'][0]['ports']['8081'] = True
    verify_timed_trace(changed, 'Invariant ObservedPortsMatch is violated')
    changed = copy.deepcopy(trace)
    changed['observations'][0]['peer'] = False
    verify_timed_trace(changed, 'Invariant ObservedPeerMatches is violated')
    changed = copy.deepcopy(trace)
    index = next(i for i, edge in enumerate(changed['edges']) if edge == {'action': 'Expire', 'decision': 'a'})
    changed['states'][index + 1].update(kernel=None, registry=None)
    verify_timed_trace(changed, 'Deadlock reached')
    changed = copy.deepcopy(trace)
    index = next(i for i, edge in enumerate(changed['edges']) if edge['action'] == 'Collect')
    changed['states'][index + 1]['tcpConsumed'] = ['a']
    verify_timed_trace(changed, 'Deadlock reached')
    changed = copy.deepcopy(trace)
    index = next(i for i, edge in enumerate(changed['edges']) if edge['action'] == 'RejectWgExpired')
    changed['edges'][index]['action'] = 'WgApply'
    verify_timed_trace(changed, 'Deadlock reached')
    changed = copy.deepcopy(trace)
    index = next(i for i, edge in enumerate(changed['edges']) if edge['action'] == 'Tick')
    changed['states'][index + 1]['tcpActive'] = ['a', 'c']
    verify_timed_trace(changed, 'Deadlock reached')
    for mutate in (lambda value: value.update(completed=False),
                   lambda value: value['wg_expiries'].update(a=True),
                   lambda value: value['edges'][0].update(action='UnknownTimedAction'),
                   lambda value: value['states'][0].update(extra=False),
                   lambda value: value['observations'][0]['ports'].pop('8081')):
        changed = copy.deepcopy(trace)
        mutate(changed)
        try:
            encode_timed_trace(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid timed schema accepted')
    changed = copy.deepcopy(trace)
    index = next(i for i, edge in enumerate(changed['edges']) if edge['action'] == 'RejectTcpReplay')
    changed['edges'][index]['action'] = 'TcpApply'
    verify_timed_trace(changed, 'Deadlock reached')
    print('Timed replay: 7 semantic counterexamples and 5 fail-closed schema cases checked')


def verify_trace(trace):
    if trace.get('scenario') == 'live':
        verify_live_trace(trace)
    elif trace.get('scenario') == 'time-and-command-failures':
        verify_timed_trace(trace)
    else:
        raise ValueError('unknown scenario; nothing skipped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', nargs='*', type=Path)
    parser.add_argument('--scenario', choices=['live', 'time-and-command-failures'], help='explicitly select one supported scenario')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--check-tools', action='store_true')
    args = parser.parse_args()
    if not args.artifacts and not args.self_test and not args.check_tools:
        parser.error('supply artifacts, --self-test or --check-tools')
    if args.check_tools:
        checker()
        print('Pinned TLC is ready')
    if args.self_test:
        self_test()
        self_test_timed()
    for artifact in args.artifacts:
        traces = json.loads(artifact.read_text())
        if not isinstance(traces, list) or not traces:
            raise ValueError('artifact must contain at least one trace')
        selected = [trace for trace in traces if args.scenario is None or trace.get('scenario') == args.scenario]
        if not selected:
            raise ValueError('no matching traces; nothing checked')
        for trace in selected:
            verify_trace(trace)


if __name__ == '__main__':
    main()
