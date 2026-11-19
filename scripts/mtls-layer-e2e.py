#!/usr/bin/env python3
"""Real client-certificate revocation over an LXC underlay, independent of WG."""
from http import client as http_client
import base64
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
        status = error.code
        raw = error.read()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = {'error':raw.decode()}
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


def status(bundle):
    return browser('window.authorityReadRevocationStatus(arguments[0]).then(value=>done({value})).catch(e=>done({error:e.message}));', [bundle['decision_id']])


def drained(bundle):
    for _ in range(100):
        value = status(bundle)
        assert value['committed'], value
        if value['mtls_sessions_drained']:
            return
        time.sleep(0.1)
    raise AssertionError('replica drain deadline exceeded')


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

    def connect(ctx, port=8443):
        connection = http_client.HTTPSConnection(host, port, context=ctx, timeout=2)
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
    assert mint(first, 409)['error'] == 'authorization_replayed', 'other issuer accepted a consumed nonce'
    first_ctx, other_ctx = context(first_cert), context(other_cert)
    existing, identity = connect(first_ctx)
    assert identity['decision_id'] == first['decision_id']
    other, other_identity = connect(other_ctx)
    assert other_identity['decision_id'] == independent['decision_id']
    other.request('GET', '/whoami')
    other_response = other.getresponse()
    assert other_response.status == 200
    other_response.read()
    second_existing, _ = connect(first_ctx, 8444)
    ca_path = root / '.secrets/mtls-ca-cert.pem'
    cert_path = directory / f'client-{first_cert["decision_id"]}.pem'
    pki = subprocess.check_output(['openssl', 'x509', '-in', str(cert_path), '-noout', '-text'], text=True)
    ocsp_url = next(line.strip().split('URI:', 1)[1] for line in pki.splitlines() if 'OCSP - URI:' in line)
    crl_url = next(line.strip().split('URI:', 1)[1] for line in pki.splitlines() if 'URI:' in line and '/crl' in line)

    def ocsp(expected, serial=None):
        args = ['openssl', 'ocsp', '-issuer', str(ca_path)]
        args += ['-cert', str(cert_path)] if serial is None else ['-serial', str(serial)]
        result = subprocess.run([*args, '-url', ocsp_url, '-CAfile', str(ca_path), '-validity_period', '2', '-respout', str(directory / 'ocsp.der')], capture_output=True, text=True)
        assert result.returncode == 0 and 'Response verify OK' in result.stderr, (result.stdout, result.stderr)
        assert ': ' + expected in result.stdout, (result.stdout, result.stderr)

    ocsp('good')
    request_path, response_path = directory / 'request.der', directory / 'get-response.der'
    subprocess.run(['openssl', 'ocsp', '-issuer', str(ca_path), '-cert', str(cert_path), '-reqout', str(request_path)], check=True)
    encoded = urllib.parse.quote(base64.b64encode(request_path.read_bytes()).decode(), safe='')
    with urllib.request.urlopen(ocsp_url + '/' + encoded, timeout=5) as response:
        assert response.headers['content-type'] == 'application/ocsp-response'
        response_path.write_bytes(response.read())
    verified_get = subprocess.run(['openssl', 'ocsp', '-reqin', str(request_path), '-respin', str(response_path), '-CAfile', str(ca_path)], capture_output=True, text=True)
    assert verified_get.returncode == 0 and 'Response verify OK' in verified_get.stderr, (verified_get.stdout, verified_get.stderr)
    malformed = urllib.request.Request(ocsp_url, b'invalid ASN.1', {'content-type':'application/ocsp-request'})
    with urllib.request.urlopen(malformed, timeout=5) as response:
        malformed_path = directory / 'malformed.der'
        malformed_path.write_bytes(response.read())
    rejected = subprocess.run(['openssl', 'ocsp', '-respin', str(malformed_path)], capture_output=True, text=True)
    assert 'malformedrequest' in (rejected.stdout + rejected.stderr).lower(), (rejected.stdout, rejected.stderr)
    replayed = subprocess.run(['openssl', 'ocsp', '-issuer', str(ca_path), '-cert', str(cert_path), '-respin', str(directory / 'ocsp.der'), '-CAfile', str(ca_path)], capture_output=True, text=True)
    assert replayed.returncode != 0 and 'Nonce Verify error' in replayed.stderr, (replayed.stdout, replayed.stderr)
    ocsp('unknown', 9223372036854775806)
    notice = revoke(first)  # Commit is distinct from receipt by every replica.
    drained(first)
    ocsp('revoked')
    with urllib.request.urlopen(crl_url, timeout=5) as response:
        crl_path = directory / 'revoked.crl'
        crl_path.write_bytes(response.read())
    verified = subprocess.run(['openssl', 'crl', '-inform', 'DER', '-in', str(crl_path), '-CAfile', str(ca_path), '-verify', '-noout'], capture_output=True, text=True)
    assert verified.returncode == 0 and 'verify OK' in verified.stderr, (verified.stdout, verified.stderr)
    pem_crl = directory / 'crl.pem'
    pem_crl.write_bytes(subprocess.check_output(['openssl', 'crl', '-inform', 'DER', '-in', str(crl_path)]))
    verified = subprocess.run(['openssl', 'verify', '-CAfile', str(ca_path), '-CRLfile', str(pem_crl), '-crl_check', str(cert_path)], capture_output=True, text=True)
    assert verified.returncode != 0 and 'certificate revoked' in verified.stderr, (verified.stdout, verified.stderr)
    witness = mint(issue())
    witness_path = directory / 'fresh-witness.pem'
    witness_path.write_text(witness['certificate_pem'])
    stale = subprocess.run(['openssl', 'verify', '-attime', str(int(time.time()) + 32), '-CAfile', str(ca_path), '-CRLfile', str(pem_crl), '-crl_check', str(witness_path)], capture_output=True, text=True)
    assert stale.returncode != 0 and 'CRL has expired' in stale.stderr, (stale.stdout, stale.stderr)
    for connection in [existing, second_existing]:
        try:
            connection.request('GET', '/whoami'); connection.getresponse().read()
        except (OSError, http_client.HTTPException):
            pass
        else:
            raise AssertionError('one replica retained a revoked session')
        connection.close()
    other.request('GET', '/whoami')
    still_live = other.getresponse()
    assert still_live.status == 200
    still_live.read()
    assert denied(first_ctx), 'revoked certificate admitted a new TLS connection'
    other.request('GET', '/whoami')
    other_after = other.getresponse()
    assert other_after.status == 200
    other_after.read()
    other.close()
    for origin in [issuer, service]:
        duplicate = http(origin + '/v1/revocations', notice)
        assert duplicate['decision_id'] == first['decision_id']
    revoked_unissued = revoke(unissued)
    drained(unissued)
    assert mint(unissued, 401)['error'] == 'mtls_authorization_revoked'
    subprocess.run(['mise', 'run', 'mesh:mtls:restart'], check=True)
    for _ in range(50):
        try:
            http(service + '/health', expected=204)
            break
        except (OSError, urllib.error.URLError, AssertionError):
            time.sleep(0.1)
    assert denied(first_ctx), 'restart lost the durable service tombstone'
    continued, _ = connect(other_ctx)
    continued.close()
    assert revoke(first) == notice, 'duplicate publication changed the signed notice'
    assert mint(unissued, 401)['error'] == 'mtls_authorization_revoked'
    # A third issuer and its restarted process use the same shared authority.
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
        'AUTHORITY_PKI_PUBLIC_ORIGIN': os.environ['AUTHORITY_PKI_PUBLIC_ORIGIN']}
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
                    except (OSError, urllib.error.URLError, AssertionError):
                        time.sleep(0.05)
                rejected = http(alternate + '/v1/mtls-certificates',
                    {'authorization':unissued['mtls_authorization'], 'public_key_pem':public_key}, expected=401)
                assert rejected['error'] == 'mtls_authorization_revoked'
                process.terminate(); process.wait(timeout=5); process = None
        finally:
            if process is not None:
                process.kill(); process.wait()
    partitioned = issue()
    partition_ctx = context(mint(partitioned))
    primary_session, _ = connect(partition_ctx)
    peer_session, _ = connect(partition_ctx, 8444)
    subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:mtls-partition'], check=True)
    try:
        time.sleep(0.2)  # The proxy closes already-open DB sockets, not just new connects.
        revoke(partitioned)
        assert not status(partitioned)['mtls_sessions_drained'], 'partitioned epoch was acknowledged without drain/lease expiry'
        drained(partitioned)
        for connection in [primary_session, peer_session]:
            try:
                connection.request('GET', '/whoami'); connection.getresponse().read()
            except (OSError, http_client.HTTPException):
                pass
            else:
                raise AssertionError('DB-partitioned replica served a revoked session after lease expiry')
            connection.close()
    finally:
        subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:mtls-restore'], check=True)
    for _ in range(100):
        try:
            http(service + '/health', expected=204)
            break
        except (OSError, urllib.error.URLError, AssertionError):
            time.sleep(0.1)
    assert denied(partition_ctx), 'recovered epoch admitted a revoked certificate'
    recovery_ctx = context(mint(issue()))
    recovery, _ = connect(recovery_ctx); recovery.close()
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
        revoke(pending)
        assert not status(pending)['mtls_sessions_drained'], 'stopped replica was counted before its lease expired'
        drained(pending)
        assert mint(pending, 401)['error'] == 'mtls_authorization_revoked'
    finally:
        subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:mtls-start'], check=True)
    # Wait for the service to be reachable before testing the dispatcher retry;
    # a refused TCP connection alone must not count as enforced revocation.
    for _ in range(50):
        try:
            http(service + '/health', expected=204)
            break
        except (OSError, urllib.error.URLError, AssertionError):
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
    print('mTLS LXC: two CP/issuer/service replicas, standard OpenSSL CRL/OCSP verification, global replay rejection, shared restart and lease expiry;  CA/binding admission, new/established connection revocation, independent decision, '
          'unissued authorization rejection, duplicate delivery, issuer/service durable restart, TLS expiry and pending-delivery recovery verified', flush=True)
