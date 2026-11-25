"""Probe regressions without requiring root or an installed kernel policy."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('endpoint_probe', Path(__file__).resolve().parent.parent / 'deploy/lxc/endpoint-probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

class ProbeTests(unittest.TestCase):
    def layout(self, document):
        with patch.object(probe, 'run', return_value=json.dumps(document)):
            return probe.nft_layout()

    def test_only_mutable_set_elements_handles_and_counters_are_ignored(self):
        base = {'nftables': [{'metainfo': {'version': '1'}}, {'set': {'name': 'allowed', 'type': 'ipv4_addr . ipv4_addr . inet_service', 'flags': ['timeout']}},
            {'chain': {'name': 'inbound', 'hook': 'input', 'prio': -10}},
            {'rule': {'handle': 1, 'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'match': {'right': {'set': [8080, 8081]}}}, {'reject': {'type': 'tcp reset'}}]}}]}
        active = copy.deepcopy(base)
        active['nftables'][1]['set']['elem'] = [{'val': ['10.77.0.1', '10.77.0.2', 8080], 'expires': 1000}]
        active['nftables'][3]['rule']['handle'] = 19
        active['nftables'][3]['rule']['expr'][0]['counter']['packets'] = 12
        self.assertEqual(self.layout(base), self.layout(active))
        for mutate in [lambda d: d['nftables'][2]['chain'].update(hook='forward'),
                       lambda d: d['nftables'][3]['rule']['expr'][1]['match'].update(right={'set': [8080]}),
                       lambda d: d['nftables'][3]['rule']['expr'].pop(),
                       lambda d: d['nftables'][1]['set'].update(flags=[]),
                       lambda d: d['nftables'][3]['rule']['expr'].append({'elem': 'unexpected rule'})]:
            changed = copy.deepcopy(base)
            mutate(changed)
            self.assertNotEqual(self.layout(base), self.layout(changed))

    def test_ssh_receipt_binds_loaded_configuration_process_and_exact_ca_set(self):
        import base64
        import hashlib
        ca = '/etc/ssh/authority-user-ca.pub'
        principals = '/etc/ssh/auth_principals/deploy'
        files = {ca: 'ca-digest', principals: 'principal-digest', '/usr/local/lib/authority/ssh-guard.py': 'guard-digest'}
        process = [123, '456', 'boot-id']
        receipt = {'files': files, 'process': process}
        key = b'fixture-ssh-ca'
        encoded = base64.b64encode(key).decode()
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
        resources = {'source': '10.77.0.1', 'principal': 'deploy', 'ssh_ca_fingerprints': [fingerprint]}
        config = f'pubkeyauthentication yes\nauthorizedprincipalscommand /usr/local/lib/authority/ssh-guard.py authorize %u %i\nauthorizedprincipalscommanduser root\ntrustedusercakeys {ca}\nauthorizedprincipalsfile none\nauthorizedkeysfile none\nusepam no\n'
        def contents(path, *args, **kwargs):
            return {str(probe.RECEIPT): json.dumps(receipt), ca: f'ssh-ed25519 {encoded} fixture', principals: 'deploy\n'}[str(path)]
        with (patch.object(probe, 'ssh_files', return_value=files),
              patch.object(probe, 'process', return_value=process),
              patch.object(probe, 'run', return_value=config),
              patch.object(Path, 'read_text', contents)):
            self.assertEqual(probe.ssh_probe(resources), receipt)
            for before, after in [('authorizedprincipalsfile none', 'authorizedprincipalsfile /etc/ssh/auth_principals/%u'), ('usepam no', 'usepam yes'), ('authorizedkeysfile none', 'authorizedkeysfile .ssh/authorized_keys'), ('authorizedprincipalscommanduser root', 'authorizedprincipalscommanduser nobody')]:
                with patch.object(probe, 'run', return_value=config.replace(before, after)):
                    with self.assertRaises(ValueError): probe.ssh_probe(resources)

            with patch.object(probe, 'process', return_value=[124, '789', 'boot-id']):
                with self.assertRaises(ValueError): probe.ssh_probe(resources)
            with patch.object(probe, 'ssh_files', return_value={ca: 'changed'}):
                with self.assertRaises(ValueError): probe.ssh_probe(resources)
            with self.assertRaises(ValueError):
                probe.ssh_probe({**resources, 'ssh_ca_fingerprints': ['SHA256:wrong-ca']})

    def test_managed_ports_are_symbolic_and_every_kernel_predicate_must_agree(self):
        layout = {'nftables': [
            {'rule': {'family': 'inet', 'table': 'authority_tcp', 'expr': [
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': field}},
                           'right': {'range': [1024, 65535]}}}
            ]}} for field in ('dport', 'dport', 'sport', 'sport')
        ]}
        self.assertEqual(probe.managed_tcp_ports(layout), [{'start': 1024, 'end': 65536}])
        changed = copy.deepcopy(layout)
        changed['nftables'][0]['rule']['expr'][0]['match']['right'] = {'set': [8080, 8082]}
        with self.assertRaises(ValueError): probe.managed_tcp_ports(changed)
        changed = copy.deepcopy(layout)
        changed['nftables'][0]['rule']['expr'][0]['match']['op'] = '!='
        with self.assertRaises(ValueError): probe.managed_tcp_ports(changed)
        with self.assertRaises(ValueError): probe.managed_tcp_ports({'nftables': layout['nftables'][:3]})

    def test_missing_and_changed_kernel_tables_withdraw_tcp_fact(self):
        request = {'signed': {'challenge': {'resources': {}}}, 'interface': 'wg0', 'nft_layout': {'expected': True}}
        for layout in [{}, {'expected': False}]:
            with (patch.object(probe, 'ssh_probe', side_effect=ValueError('stale sshd')),
                  patch.object(probe, 'mtls_probe', side_effect=ValueError('stopped TLS')),
                  patch.object(probe, 'nft_layout', return_value=layout),
                  patch.object(probe, 'run', side_effect=ValueError('missing route'))):
                report = probe.probe(request)
                self.assertEqual(report['facts'], [])
                self.assertEqual(len(report['errors']), 4)
                self.assertEqual(len(report['configuration_sha256']), 64)

if __name__ == '__main__':
    unittest.main()
