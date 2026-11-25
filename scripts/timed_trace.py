from tcp_resources import ports as port_intervals
"""Logical timed state reconstruction; TLC independently checks each recorded edge."""
import time

SET_FIELDS = ('consumed', 'tombstones', 'published', 'completed', 'timers',
              'tcpConsumed', 'tcpActive', 'tcpPublished', 'tcpTombstones', 'tcpCompleted')
WG_FIELDS = ('now', 'ready', 'kernel', 'registry', 'consumed', 'tombstones',
             'published', 'completed', 'timers', 'badCleanup')
TCP_FIELDS = ('tcpConsumed', 'tcpActive', 'tcpPublished', 'tcpTombstones', 'tcpCompleted')


class TimedTrace:
    def __init__(self, trace):
        self.epoch = int(time.time())
        self.trace = trace
        trace.update(version=2, completed=False, states=[], edges=[], observations=[],
                     wg_expiries={}, tcp_expiries={}, tcp_ports={})
        self.state = {'now': 0, 'ready': True, 'kernel': None, 'registry': None, 'badCleanup': False,
                      **{key: set() for key in SET_FIELDS}}
        self.snapshot()

    def register(self, name, value, requested_ports):
        if name in self.trace['tcp_expiries'] or name in self.trace['wg_expiries']:
            raise ValueError('a timed binding cannot change its immutable expiry')
        tcp = value['tcp_grant']['grant']
        self.trace['tcp_expiries'][name] = tcp['expires_at'] - self.epoch
        assert tcp['resources']['destination_ports'] == port_intervals(requested_ports), 'issued TCP scope differs from request'
        self.trace['tcp_ports'][name] = list(requested_ports)
        if 'network_grant' in value:
            self.trace['wg_expiries'][name] = value['network_grant']['grant']['expires_at'] - self.epoch

    def snapshot(self, action=None, decision=None):
        self.trace['states'].append({key: sorted(value) if isinstance(value, set) else value
                                    for key, value in self.state.items()})
        if action:
            self.trace['edges'].append({'action': action, 'decision': decision})

    def advance(self):
        while self.state['now'] < int(time.time()) - self.epoch:
            self.state['now'] += 1
            self.state['tcpActive'] = {d for d in self.state['tcpActive']
                                       if self.trace['tcp_expiries'][d] > self.state['now']}
            self.snapshot('Tick')

    def action(self, action, decision=None):
        self.advance()
        s, d = self.state, decision
        if action == 'WgApply':
            s['consumed'].add(d)
            s['kernel'] = s['registry'] = d
            s['timers'].add(d)
        elif action in {'WgPublish', 'WgPersist'}:
            s['published' if action == 'WgPublish' else 'tombstones'].add(d)
        elif action == 'WgComplete':
            if s['registry'] == d:
                s['kernel'] = s['registry'] = None
            s['completed'].add(d)
        elif action == 'Expire':
            if s['registry'] == d:
                s['kernel'] = s['registry'] = None
            s['timers'].discard(d)
        elif action == 'TcpApply':
            s['tcpConsumed'].add(d)
            s['tcpActive'].add(d)
        elif action in {'TcpPublish', 'TcpPersist'}:
            s['tcpPublished' if action == 'TcpPublish' else 'tcpTombstones'].add(d)
        elif action == 'TcpComplete':
            s['tcpActive'].discard(d)
            s['tcpCompleted'].add(d)
        elif action == 'Crash':
            s['ready'] = False
            s['registry'] = None
            s['timers'].clear()
        elif action == 'Collect':
            for field, expiry in [('consumed', 'wg_expiries'), ('tombstones', 'wg_expiries'),
                                  ('tcpConsumed', 'tcp_expiries'), ('tcpTombstones', 'tcp_expiries')]:
                def deadline(d):
                    value = self.trace[expiry][d]
                    return max(value, self.trace['wg_expiries'].get(d, value)) if field == 'tcpTombstones' else value
                s[field] = {d for d in s[field] if deadline(d) > s['now']}
        elif action == 'Recover':
            s['ready'] = True
            s['kernel'] = None
            s['tcpActive'].clear()
        elif action not in {'FailExpire', 'FailRevoke', 'RejectWgExpired', 'RejectTcpExpired',
                            'RejectWgRevoked', 'RejectTcpReplay', 'Stutter'}:
            raise ValueError(f'unsupported timed action {action}')
        self.snapshot(action, decision)

    def observe(self, ports, peer):
        self.trace['observations'].append({'state_index': len(self.trace['states']),
                                           'ports': dict(ports), 'peer': peer})
