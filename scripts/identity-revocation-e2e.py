#!/usr/bin/env python3
"""Root-signed identity fences against real WG/TCP/SSH/mTLS enforcement."""
from http import client as http_client
import base64
import copy
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from tcp_probe import echo

session, control, issuer, node, agent, client = sys.argv[1:]
root = Path(__file__).resolve().parents[1]
host = urllib.parse.urlparse(agent).hostname

def http(url, body=None, headers=None, expected=200):
    req = urllib.request.Request(url, None if body is None else json.dumps(body).encode(),
                                 {'content-type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            status, value = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        status, value = error.code, json.load(error)
    assert status == expected, (url, status, value)
    return value

def browser(script, args=None):
    result = http(f'http://127.0.0.1:9515/session/{session}/execute/async', {
        'script': 'const done=arguments[arguments.length-1]; ' + script, 'args': args or []})['value']
    assert 'error' not in result, result
    return result.get('value')

def issue():
    prepared = browser('window.authorityPrepareAccessAuthorization().then(value=>done({value})).catch(e=>done({error:e.message}));')
    return http(control + '/v1/access-authorizations', prepared['body'], prepared['headers'])

def until(predicate, message, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError(message)

def login(old_token):
    browser("document.querySelector('#login').click();done({value:true});")
    def ready():
        state = browser("done({value:{token:sessionStorage.getItem('authority-session'),busy:document.querySelector('#login').disabled,status:document.querySelector('#result').textContent.slice(0,160)}});")
        if not state['busy'] and state['token'] != old_token:
            assert state['status'].startswith('Authenticated, authorized, and issued.'), state['status']
            return True
        return False
    until(ready, 'fresh passkey authentication failed', 15)

with tempfile.TemporaryDirectory(prefix='authority-identity-e2e-') as directory:
    directory = Path(directory)
    subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_mesh:test-tcp-cidr'],check=True,stdout=subprocess.DEVNULL)
    initial = issue()
    fixture = {**initial['ssh_authorization']['generation'], 'target_node_id': initial['ssh_authorization']['authorization']['target_node_id']}
    fixture_path = root / '.secrets/e2e-identity-fixture.json'
    fixture_path.write_text(json.dumps(fixture))
    subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_db:test-resource-range'],check=True,stdout=subprocess.DEVNULL)
    fixture_path.unlink()
    try:
        subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_mesh:test-tcp-wide'],check=True,stdout=subprocess.DEVNULL)
        wide = browser('window.authorityRequestTcpAuthorization(["8080-8180"],true,30).then(value=>done({value})).catch(e=>done({error:e.message}));')
        assert wide['tcp_grant']['grant']['resources']['destination_ports'] == [{'start':8080,'end':8181}]
        http(agent + '/v1/network-grants',wide['network_grant'])
        http(agent + '/v1/tcp-grants',wide['tcp_grant'])
        subprocess.run(['mise','run','mesh:client:reconnect'],check=True,stdout=subprocess.DEVNULL)
        for port in (2223,2224):
            with socket.create_connection((client,port),timeout=2) as stream:
                echo(stream)
        subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_mesh:test-tcp-range-present'],check=True,stdout=subprocess.DEVNULL)
        denied = browser('window.authorityRequestTcpAuthorization(["8080-8181"],false,10).then(()=>done({value:false})).catch(()=>done({value:true}));')
        assert denied, 'unattested port range was authorized'
        automatic = browser('window.authorityRequestTcpAuthorization([8080],false,10,true).then(value=>done({value})).catch(e=>done({error:e.message}));')
        assert automatic['tcp_grant']['grant']['resources']['destination_ports'] == [{'start':8080,'end':8081}]
        print('Symbolic TCP range: 101 ports signed/projected as one interval, native nft range and both real services verified; unsupported coverage denied',flush=True)
    finally:
        subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_mesh:test-tcp-normal'],check=True,stdout=subprocess.DEVNULL)
    for selector in ('device', 'subject'):
        active, unapplied = issue(), issue()
        identity = active['ssh_authorization']['generation']
        domain, subject, device = (identity[key] for key in ('domain_id', 'subject_user_id', 'device_id'))
        http(agent + '/v1/network-grants', active['network_grant'])
        tcp = browser('window.authorityRequestTcpAuthorization([8080],false,40).then(value=>done({value})).catch(e=>done({error:e.message}));')
        http(agent + '/v1/tcp-grants', tcp['tcp_grant'])
        subprocess.run(['mise','run','mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
        ssh_key = http(node + '/v1/ssh-key')
        certificate = http(issuer + '/v1/ssh-certificates', {'authorization': active['ssh_authorization'], 'ssh_public_key': ssh_key['public_key']})
        private_key = directory / 'id_ed25519'
        private_key.write_bytes((root / '.secrets/poc-ssh/id_ed25519').read_bytes())
        private_key.chmod(0o600)
        cert_file = directory / 'ssh-cert.pub'
        cert_file.write_text(certificate['certificate'])
        ssh = subprocess.Popen(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=no',
            '-o','UserKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','ConnectTimeout=4',
            '-F','/dev/null','-o',f'CertificateFile={cert_file}','-i',str(private_key),
            '-p','2222',f'deploy@{client}', 'printf IDENTITY_SSH_READY; sleep 120'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        streams = []
        try:
            assert select.select([ssh.stdout], [], [], 5)[0], 'SSH guard admission timed out'
            marker = ssh.stdout.read(len(b'IDENTITY_SSH_READY'))
            if marker != b'IDENTITY_SSH_READY':
                subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_mesh:ssh-guard-status'],check=False)
                raise AssertionError(('SSH certificate was not admitted',ssh.stderr.read().decode()[-2000:]))
            tcp_stream = socket.create_connection((client,2223), timeout=2)
            streams.append(tcp_stream)
            echo(tcp_stream)
            mtls_key = http(node + '/v1/mtls-key')
            mtls_cert = http(issuer + '/v1/mtls-certificates', {'authorization':active['mtls_authorization'], 'public_key_pem':mtls_key['public_key_pem']})
            mtls_file = directory / 'mtls-cert.pem'
            mtls_file.write_text(mtls_cert['certificate_pem'])
            ctx = ssl.create_default_context(cafile=str(root / '.secrets/mtls-server-cert.pem'))
            ctx.load_cert_chain(mtls_file, root / '.secrets/poc-mtls/client-key.pem')
            for port in (8443,8444):
                connection = http_client.HTTPSConnection(host, port, context=ctx, timeout=2)
                connection.request('GET','/whoami')
                response = connection.getresponse()
                assert response.status == 200
                response.read()
                streams.append(connection)
            old_token = browser("done({value:sessionStorage.getItem('authority-session')});")
            environment = {**os.environ, 'AUTHORITY_SIGNING_KEY_FILE':str(root / '.secrets/control-plane-ed25519.pem')}
            result = subprocess.run([str(root / 'target/debug/authority-admin'), control, domain, selector,
                device if selector == 'device' else subject], env=environment, check=True, capture_output=True, text=True, timeout=35)
            receipt = json.loads(result.stdout)
            assert receipt['completed'] and receipt['pending_receivers'] == 0, receipt
            assert receipt['notices'], 'no selector fence was published'
            # A replayed, committed operation cannot advance the epoch twice.
            environment['AUTHORITY_OPERATION_NONCE'] = receipt['operation_nonce']
            duplicate = subprocess.run([str(root / 'target/debug/authority-admin'), control, domain, selector,
                device if selector == 'device' else subject], env=environment, check=True, capture_output=True, text=True, timeout=10)
            assert json.loads(duplicate.stdout)['selector'] == receipt['selector']
            until(lambda: ssh.poll() is not None, 'existing SSH process survived committed identity fence')
            try:
                echo(tcp_stream)
            except (OSError, AssertionError):
                pass
            else:
                raise AssertionError('existing TCP flow survived identity fence')
            for connection in streams[1:]:
                try:
                    connection.request('GET','/whoami'); response = connection.getresponse(); response.read()
                except (OSError, http_client.HTTPException):
                    pass
                else:
                    raise AssertionError('existing mTLS flow survived identity fence')
            assert http(agent + '/v1/network-grants', unapplied['network_grant'], expected=409)['error'] == 'identity_generation_revoked'
            # Old, never redeemed SSH/mTLS credentials cannot race past the DB fence.
            http(issuer + '/v1/ssh-certificates', {'authorization':unapplied['ssh_authorization'], 'ssh_public_key':ssh_key['public_key']}, expected=401)
            http(issuer + '/v1/mtls-certificates', {'authorization':unapplied['mtls_authorization'], 'public_key_pem':mtls_key['public_key_pem']}, expected=401)
            prepared = browser('window.authorityPrepareAccessAuthorization().then(value=>done({value})).catch(e=>done({error:e.message}));')
            http(control + '/v1/access-authorizations', prepared['body'], prepared['headers'], expected=401)
            subprocess.run(['mise','run','mesh:agent:restart'],check=True,stdout=subprocess.DEVNULL)
            assert http(agent + '/v1/network-grants', unapplied['network_grant'], expected=409)['error'] == 'identity_generation_revoked'
            # Explicit trusted administrator recovery advances generations again;
            # it must never reactivate the session/grants from the compromised epoch.
            (root / '.secrets/e2e-identity-fixture.json').write_text(json.dumps(identity))
            subprocess.run([str(root / 'scripts/authority-agent.sh'),'run','_db:test-identity-reenable'],check=True,stdout=subprocess.DEVNULL)
            (root / '.secrets/e2e-identity-fixture.json').unlink()
            prepared = browser('window.authorityPrepareAccessAuthorization().then(value=>done({value})).catch(e=>done({error:e.message}));')
            http(control + '/v1/access-authorizations', prepared['body'], prepared['headers'], expected=401)
            login(old_token)
            fresh = issue()
            current = fresh['ssh_authorization']['generation']
            field = 'device_generation' if selector == 'device' else 'subject_generation'
            assert current[field] > identity[field], (identity,current)
            print(f'Identity revocation ({selector}): signed generation fence, live SSH/TCP/mTLS teardown, issuer fence, durable restart and fresh-epoch recovery OK', flush=True)
        finally:
            for stream in streams:
                stream.close()
            if ssh.poll() is None:
                ssh.terminate()
            ssh.wait(timeout=5)
