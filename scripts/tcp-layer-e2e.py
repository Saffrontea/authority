#!/usr/bin/env python3
from tcp_resources import ports as port_intervals, host as host_interval
"""Exercise signed TCP derivation and real kernel enforcement over the mesh."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from tcp_probe import echo, probe as probe_tcp

session, control, agent, client = sys.argv[1:]


def http(url, body, expected=200, headers=None):
    request = urllib.request.Request(url, json.dumps(body).encode(),
                                     {'content-type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, value = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        status, value = error.code, json.load(error)
    assert status == expected, (url, status, value)
    return value


def browser(script, args):
    value = http(f'http://127.0.0.1:9515/session/{session}/execute/async', {
        'script': 'const done=arguments[arguments.length-1]; ' + script,
        'args': args,
    })['value']
    assert 'error' not in value, value
    return value


def issue(ports, ttl=20, network=False, automatic=False):
    return browser('window.authorityRequestTcpAuthorization(arguments[0],arguments[1],arguments[2],arguments[3])'
                   '.then(value=>done({value})).catch(error=>done({error:error.message}));',
                   [ports, network, ttl, automatic])['value']


def revoke(decision, kinds):
    return browser('window.authorityRevokeDecision(arguments[0],arguments[1])'
                   '.then(value=>done({value})).catch(error=>done({error:error.message}));',
                   [decision, kinds])['value']


def pull(target, after):
    return browser('window.authorityPullRevocations(arguments[0],arguments[1])'
                   '.then(value=>done({value})).catch(error=>done({error:error.message}));', [target, after])['value']


def connect(port, timeout=1):
    stream = socket.create_connection((client, port), timeout=timeout)
    stream.settimeout(timeout)
    return stream


def probe(port, timeout=1):
    return probe_tcp(client, port, timeout)


def allowed(port, timeout=1):
    return probe(port, timeout)['admitted']


def wait(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    subprocess.run(['mise', 'run', 'mesh:agent:status'], check=False)
    raise AssertionError('TCP enforcement deadline exceeded')


# Both listeners exist but TCP grants are absent. Mesh membership alone does
# not authorize either managed TCP service.
assert not allowed(2223) and not allowed(2224)
rejected = browser('window.authorityRequestTcpAuthorization([8082],false,10)'
                   '.then(value=>done({unexpected:value})).catch(error=>done({denial:error.message}));', [])
assert 'tcp_port_denied' in rejected.get('denial', ''), rejected

# These witnesses must outlive the separate short-expiry test below.
combined = issue([8080], ttl=40, network=True)
assert combined['decision_id'] == combined['tcp_grant']['grant']['decision_id']
assert combined['decision_id'] == combined['network_grant']['grant']['nonce']
assert 'ssh_authorization' not in combined and 'mtls_authorization' not in combined
assert combined['tcp_grant']['grant']['resources']['source_addresses'] == host_interval('10.77.0.1')
assert combined['tcp_grant']['grant']['resources']['destination_addresses'] == host_interval('10.77.0.2')
http(f'{agent}/v1/network-grants', combined['network_grant'])
http(f'{agent}/v1/tcp-grants', combined['tcp_grant'])
# Live observation withdrawal can discard the server's previous WG session.
# Fresh authorization also refreshes the client transport, as after agent restart.
subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
wait(lambda: allowed(2223))
assert not allowed(2224), 'unselected port was admitted'

# TCP-only selection emits no peer or credential contracts.
other = issue([8081], ttl=40)
assert set(other) == {'decision_id', 'tcp_grant'}, other
http(f'{agent}/v1/tcp-grants', other['tcp_grant'])
wait(lambda: allowed(2224))
replay = http(f'{agent}/v1/tcp-grants', combined['tcp_grant'], 409)
assert replay['error'] == 'tcp_grant_replayed'
tampered = copy.deepcopy(combined['tcp_grant'])
tampered['grant']['resources']['destination_ports'] = port_intervals([8081])
assert http(f'{agent}/v1/tcp-grants', tampered, 401)['error'] == 'invalid_tcp_grant'

# The selection is part of the authenticated request, not an unsigned hint.
prepared = browser('window.authorityPrepareRevocation(arguments[0],"user_requested",["tcp.port"])'
                   '.then(value=>done({value})).catch(error=>done({error:error.message}));',
                   [combined['decision_id']])['value']
prepared['body']['adapter_kinds'] = ['wireguard.peer']
http(f'{control}/v1/access-authorizations/{combined["decision_id"]}/revocations',
     prepared['body'], 401, prepared['headers'])

with connect(2223) as existing:
    echo(existing)
    notice = revoke(combined['decision_id'], ['tcp.port'])
    assert notice['notice']['adapter_kinds'] == ['tcp.port']
    wait(lambda: not allowed(2223))
    try:
        echo(existing)
    except (OSError, AssertionError):
        pass
    else:
        raise AssertionError('existing TCP stream survived revocation')
assert time.time() < combined['tcp_grant']['grant']['expires_at'], 'denial was only expiry'
assert allowed(2224), 'TCP revocation affected another decision/port'
assert subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0, 'TCP revocation removed peer'
assert http(f'{agent}/v1/tcp-grants', combined['tcp_grant'], 409)['error'] == 'tcp_grant_revoked'
print('TCP selection: one port admitted, unselected port denied; TCP-only projection needs no SSH/mTLS/peer', flush=True)
print('TCP revocation: new and existing streams denied; another TCP grant and WireGuard remain active', flush=True)

# A revocation can arrive before a still-unconsumed grant.
late = issue([8080], ttl=10)
late_notice = revoke(late['decision_id'], ['tcp.port'])
http(f'{agent}/v1/revocations', late_notice)
assert http(f'{agent}/v1/tcp-grants', late['tcp_grant'], 409)['error'] == 'tcp_grant_revoked'

# Independent TCP expiry is enforced by the kernel even for an existing stream.
short = issue([8080], ttl=3)
http(f'{agent}/v1/tcp-grants', short['tcp_grant'])
with connect(2223) as existing:
    echo(existing)
    deadline = short['tcp_grant']['grant']['expires_at']
    time.sleep(max(0, deadline - time.time() + 0.2))
    assert not allowed(2223)
    try:
        echo(existing)
    except (OSError, AssertionError):
        pass
    else:
        raise AssertionError('existing TCP stream survived expiry')
assert allowed(2224), 'one TCP grant expiry removed another grant'
assert subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0

# Retire the independent service grant before later tests restore mesh transport.
revoke(other['decision_id'], ['tcp.port'])
wait(lambda: not allowed(2224))

# A second scope on the same decision is a separate durable notice.
network_notice = revoke(combined['decision_id'], ['wireguard.peer'])
assert network_notice['notice']['sequence'] > notice['notice']['sequence']
assert network_notice['notice']['adapter_kinds'] == ['wireguard.peer']
# Repeating an earlier scope must return its original sequence even after a
# broader scope has been recorded for the same decision.
assert revoke(combined['decision_id'], ['tcp.port'])['notice']['sequence'] == notice['notice']['sequence']
wait(lambda: subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode != 0)
assert time.time() < combined['network_grant']['grant']['expires_at'], 'peer denial was only expiry'
print('TCP expiry: active streams denied independently; later peer-only revocation has its own sequence', flush=True)

# Exercise the visible selection controls as well as the programmatic API.
def page(script):
    return http(f'http://127.0.0.1:9515/session/{session}/execute/sync', {
        'script': script, 'args': [],
    })['value']


page("const issue=window.authorityRequestTcpAuthorization;"
     "window.authorityRequestTcpAuthorization=async(...args)=>{const value=await issue(...args);"
     "window.__e2eTcpUiDecisionId=value.decision_id;return value;};"
     "document.querySelector('#tcp-ports').value='8080';"
     "document.querySelector('#tcp-ttl').value='10';"
     "document.querySelector('#tcp-network').checked=true;"
     "document.querySelector('#tcp-form').requestSubmit(); return true;")
wait(lambda: page("return document.querySelector('#tcp-result').textContent;").startswith('TCP access allowed.'))
page("document.querySelector('#tcp-revoke').click(); return true;")
wait(lambda: page("return document.querySelector('#tcp-result').textContent;").startswith('TCP revocation recorded.'))
print('TCP UI: port/lifetime/network selection and TCP-only revocation succeeded', flush=True)

ui_decision = page("return window.__e2eTcpUiDecisionId;")
# A fresh target peer after revocation needs the client's old transport session
# reset as well. This does not install or alter any target-side peer or TCP grant.
subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True)
wait(lambda: subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode == 0)

# Flip automatic mode after the browser signed its proof: the server must reject it.
mode_tamper = browser(
    "const original=window.fetch;"
    "window.fetch=(url,options)=>{if(String(url).endsWith('/v1/tcp-authorizations')){"
    "window.fetch=original;const body=JSON.parse(options.body);body.automatic_route=false;"
    "return original(url,{...options,body:JSON.stringify(body)});}return original(url,options);};"
    "window.authorityRequestTcpAuthorization([8080],false,10,true)"
    ".then(value=>done({unexpected:true})).catch(error=>done({denial:error.message}))"
    ".finally(()=>{window.fetch=original;});", [])
assert 'invalid_device_proof' in mode_tamper.get('denial', ''), mode_tamper

# The same browser API selects either the declared existing route or a mesh grant.
automatic = issue([8080], ttl=10, automatic=True)
existing_source = os.environ.get('AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS')
expect_network = (existing_source is None or host_interval(existing_source)
                  != automatic['tcp_grant']['grant']['resources']['source_addresses'])
assert ('network_grant' in automatic) == expect_network, automatic
assert automatic['tcp_grant']['grant']['resources']['destination_ports'] == port_intervals([8080])
if expect_network:
    http(f'{agent}/v1/network-grants', automatic['network_grant'])
http(f'{agent}/v1/tcp-grants', automatic['tcp_grant'])
wait(lambda: allowed(2223))
assert not allowed(2224), 'automatic planning admitted an unselected service'
revoke(automatic['decision_id'], ['tcp.port'])
wait(lambda: not allowed(2223))
if expect_network:
    revoke(automatic['decision_id'], ['wireguard.peer'])
# Cancel the UI test's independent peer lease before restoring static mesh state.
revoke(ui_decision, ['wireguard.peer'])
wait(lambda: subprocess.run(['mise', 'run', 'mesh:verify'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode != 0)
print('Automatic TCP planning: proof-bound mode, '
      + ('WireGuard fallback' if expect_network else 'declared existing route')
      + ', selected-port enforcement and revocation verified', flush=True)

# Run generated traces after fixed UI/protocol regressions have retired their leases.
trace_spec = importlib.util.spec_from_file_location(
    'lifecycle_trace_e2e', Path(__file__).with_name('lifecycle-trace-e2e.py'))
trace_module = importlib.util.module_from_spec(trace_spec)
trace_spec.loader.exec_module(trace_module)
trace_module.run(issue, revoke, http, wait, allowed, agent, control, probe, pull)


# A signed configuration assertion must not survive real enforcement drift.
active = issue([8080], ttl=40, network=True)
http(f'{agent}/v1/network-grants', active['network_grant'])
http(f'{agent}/v1/tcp-grants', active['tcp_grant'])
subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
wait(lambda: allowed(2223))
old_unapplied = issue([8081], ttl=40)
try:
    subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:test-observation-break'], check=True)
    denied = browser("window.authorityRequestTcpAuthorization([8081],false,10,false)"
        ".then(value=>done({unexpected:true})).catch(error=>done({denial:error.message}));", [])
    assert 'denial' in denied and not denied.get('unexpected'), denied
    wait(lambda: not allowed(2223))
finally:
    subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:agent-restart'], check=True)

def observation_agent_ready():
    try:
        with urllib.request.urlopen(agent + '/v1/identity', timeout=1) as response:
            return response.status == 200
    except OSError:
        return False
wait(observation_agent_ready)
try:
    fresh = issue([8080], ttl=20, network=True)
    http(f'{agent}/v1/network-grants', fresh['network_grant'])
    http(f'{agent}/v1/tcp-grants', fresh['tcp_grant'])
    subprocess.run(['mise', 'run', 'mesh:client:reconnect'], check=True, stdout=subprocess.DEVNULL)
    wait(lambda: allowed(2223))
    assert time.time() < old_unapplied['tcp_grant']['grant']['expires_at'], 'stale grant only failed by expiry'
    assert http(f'{agent}/v1/tcp-grants', old_unapplied['tcp_grant'], 503)['error'] == 'endpoint_observation_unavailable'
    assert not allowed(2224), 'pre-fence unapplied grant revived after enforcement repair'
finally:
    subprocess.run(['./scripts/authority-agent.sh', 'run', '_mesh:agent-restart'], check=True)
print('Endpoint observations: real nft drift denied authorization, withdrew installed access, and fenced old grants across repair/restart', flush=True)
