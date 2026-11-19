#!/usr/bin/env python3
"""Real client-certificate revocation over an LXC underlay, independent of WG."""
from http import client as http_client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

session, control, issuer, node, agent = sys.argv[1:]
root = Path(__file__).resolve().parents[1]
service = agent.rsplit(':', 1)[0] + ':3004'
host = urllib.parse.urlparse(agent).hostname


def http(url, body=None, headers=None, expected=200):
    request = urllib.request.Request(url, None if body is None else json.dumps(body).encode(),
        {'content-type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status, value = response.status, json.load(response) if response.status != 204 else None
    except urllib.error.HTTPError as error:
        status, value = error.code, json.load(error)
    assert status == expected, (url, status, value)
    return value


def browser(script, args=[]):
    result = http(f'http://127.0.0.1:9515/session/{session}/execute/async', {
        'script': 'const done=arguments[arguments.length-1]; ' + script, 'args': args})['value']
    assert 'error' not in result, result
    return result['value']


def issue():
    prepared = browser('window.authorityPrepareAccessAuthorization().then(value=>done({value})).catch(e=>done({error:e.message}));')
    return http(control + '/v1/access-authorizations', prepared['body'], prepared['headers'])


def revoke(bundle, expected=200):
    decision = bundle['decision_id']
    prepared = browser('window.authorityPrepareRevocation(arguments[0], "user_requested", ["mtls.client_certificate"])'
        '.then(value=>done({value})).catch(e=>done({error:e.message}));', [decision])
    notice = http(f'{control}/v1/access-authorizations/{decision}/revocations', prepared['body'], prepared['headers'], expected=expected)
    if expected != 200:
        return notice
    assert notice['notice']['expires_at'] >= bundle['mtls_authorization']['authorization']['expires_at']
    return notice


key = http(node + '/v1/mtls-key')
public_key = key['public_key_pem']


def mint(bundle, expected=200):
    return http(issuer + '/v1/mtls-certificates', {'authorization':bundle['mtls_authorization'], 'public_key_pem': public_key}, expected=expected)


with tempfile.TemporaryDirectory(prefix='authority-mtls-e2e-') as directory:
    directory = Path(directory)

    def context(certificate):
        path = directory / f'client-{certificate["decision_id"]}.pem'
        path.write_text(certificate['certificate_pem'])
        ctx = ssl.create_default_context(cafile=str(root / '.secrets/mtls-server-cert.pem'))
        ctx.load_cert_chain(path, root / '.secrets/poc-mtls/client-key.pem')
        return ctx

    def connect(ctx):
        connection = http_client.HTTPSConnection(host, 8443, context=ctx, timeout=2)
        connection.request('GET', '/whoami')
        response = connection.getresponse()
        assert response.status == 200
        value = json.loads(response.read())
        return connection, value

    def denied(ctx):
        try:
            connection, _ = connect(ctx)
        except (OSError, http_client.HTTPException):
            return True
        connection.close()
        return False

    empty_context = ssl.create_default_context(cafile=str(root / '.secrets/mtls-server-cert.pem'))
    assert denied(empty_context), 'TLS endpoint admitted a client without a certificate'
    first, independent, unissued = issue(), issue(), issue()
    first_cert, other_cert = mint(first), mint(independent)
    first_ctx, other_ctx = context(first_cert), context(other_cert)
    existing, identity = connect(first_ctx)
    assert identity['decision_id'] == first['decision_id']
    other, other_identity = connect(other_ctx)
    assert other_identity['decision_id'] == independent['decision_id']
    other.request('GET', '/whoami')
    other_response = other.getresponse()
    assert other_response.status == 200
    other_response.read()
    notice = revoke(first)  # HTTP success fences issuer and drains service sessions.
    other.request('GET', '/whoami')
    still_live = other.getresponse()
    assert still_live.status == 200
    still_live.read()
    assert denied(first_ctx), 'revoked certificate admitted a new TLS connection'
    try:
        existing.request('GET', '/whoami')
        existing.getresponse().read()
    except (OSError, http_client.HTTPException):
        pass
    else:
        raise AssertionError('revoked TLS keep-alive connection remained usable')
    existing.close()
    other.request('GET', '/whoami')
    other_after = other.getresponse()
    assert other_after.status == 200
    other_after.read()
    other.close()
    for origin in [issuer, service]:
        duplicate = http(origin + '/v1/revocations', notice)
        assert duplicate['decision_id'] == first['decision_id']
    revoked_unissued = revoke(unissued)
    assert mint(unissued, 401)['error'] == 'mtls_authorization_revoked'
    subprocess.run(['mise', 'run', 'mesh:mtls:restart'], check=True)
    for _ in range(50):
        try:
            http(service + '/health', expected=204)
            break
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    assert denied(first_ctx), 'restart lost the durable service tombstone'
    continued, _ = connect(other_ctx)
    continued.close()
    assert revoke(first) == notice, 'duplicate publication changed the signed notice'
    assert mint(unissued, 401)['error'] == 'mtls_authorization_revoked'
    # Exercise the issuer's real process restart with an isolated replay ledger.
    # Sharing a live ledger between processes is intentionally unsupported.
    listener = socket.socket(); listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]; listener.close()
    alternate = f'http://127.0.0.1:{port}'
    environment = {**os.environ,
        'AUTHORITY_ISSUER_BIND': f'127.0.0.1:{port}',
        'AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE': str(root / '.secrets/control-plane-ed25519.pub.pem'),
        'AUTHORITY_SSH_CA_KEY_FILE': str(root / '.secrets/ssh-ca'),
        'AUTHORITY_SSH_CA_PUBLIC_KEY_FILE': str(root / '.secrets/ssh-ca.pub'),
        'AUTHORITY_MTLS_CA_KEY_FILE': str(root / '.secrets/mtls-ca-key.pem'),
        'AUTHORITY_MTLS_CA_CERTIFICATE_FILE': str(root / '.secrets/mtls-ca-cert.pem'),
        'AUTHORITY_ISSUER_REPLAY_LEDGER_FILE': str(directory / 'restart-ledger')}
    process = None
    with (directory / 'restart.log').open('wb') as log:
        try:
            for attempt in range(2):
                process = subprocess.Popen([str(root / 'target/debug/authority-credential-issuer')], env=environment, stdout=log, stderr=log)
                for _ in range(100):
                    assert process.poll() is None, 'isolated issuer exited'
                    try:
                        http(alternate + '/health', expected=204)
                        break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.05)
                if attempt == 0:
                    http(alternate + '/v1/revocations', revoked_unissued)
                rejected = http(alternate + '/v1/mtls-certificates',
                    {'authorization':unissued['mtls_authorization'], 'public_key_pem':public_key}, expected=401)
                assert rejected['error'] == 'mtls_authorization_revoked'
                process.terminate(); process.wait(timeout=5); process = None
        finally:
            if process is not None:
                process.kill(); process.wait()
    expiring, _ = connect(other_ctx)
    while time.time() <= other_cert['expires_at'] + 0.2:
        time.sleep(min(0.25, max(0, other_cert['expires_at'] + 0.2 - time.time())))
    assert denied(other_ctx), 'expired client certificate admitted a new connection'
    try:
        expiring.request('GET', '/whoami'); expiring.getresponse().read()
    except (OSError, http_client.HTTPException):
        pass
    else:
        raise AssertionError('expired TLS session remained usable')
    expiring.close()
    pending = issue()
    pending_cert = mint(pending)
    pending_ctx = context(pending_cert)
    witness_ctx = context(mint(issue()))
    ready, _ = connect(pending_ctx); ready.close()
    subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:mtls-stop'], check=True)
    try:
        assert revoke(pending, expected=503)['error'] == 'mtls_revocation_pending'
        assert mint(pending, 401)['error'] == 'mtls_authorization_revoked'
    finally:
        subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:mtls-start'], check=True)
    # Wait for the service to be reachable before testing the dispatcher retry;
    # a refused TCP connection alone must not count as enforced revocation.
    for _ in range(50):
        try:
            http(service + '/health', expected=204)
            break
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    for _ in range(50):
        if denied(pending_ctx): break
        time.sleep(0.1)
    else:
        raise AssertionError('background retry did not fence the recovered service')
    assert time.time() + 1 < pending_cert['expires_at'], 'retry observation must precede natural expiry'
    witness, _ = connect(witness_ctx); witness.close()
    revoke(pending)  # A fresh proof retries the persisted request idempotently.
    # No WireGuard grant has been applied for any of these decisions.
    print('mTLS LXC: CA/binding admission, new/established connection revocation, independent decision, '
          'unissued authorization rejection, duplicate delivery, issuer/service durable restart, TLS expiry and pending-delivery recovery verified', flush=True)
