#!/usr/bin/env python3
"""Replay completed live E2E trace artifacts against the checked TLA+ model."""
import argparse
import copy
import json
from pathlib import Path

from tla_replay import encode_trace, verify_live_trace
from tlc_tools import checker


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', nargs='*', type=Path)
    parser.add_argument('--scenario', choices=['live'], help='explicitly select the supported live projection')
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
    for artifact in args.artifacts:
        traces = json.loads(artifact.read_text())
        if not isinstance(traces, list) or not traces:
            raise ValueError('artifact must contain at least one trace')
        selected = [trace for trace in traces if args.scenario is None or trace.get('scenario') == args.scenario]
        if not selected:
            raise ValueError('no matching traces; nothing checked')
        for trace in selected:
            verify_live_trace(trace)


if __name__ == '__main__':
    main()
