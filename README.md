# Authority PoC

This workspace demonstrates the initial end-to-end trust flow:

1. authenticate a human with a Passkey;
2. evaluate an explicit user, device, target, and principal policy;
3. verify proof of possession for both the browser device and the target
   node's LXC-held Ed25519 identity;
4. make one policy decision and project it into independently scoped SSH,
   WireGuard, and mTLS contracts;
5. independently verify the scoped contracts in the Credential Issuer and
   target Network Agent, with durable replay ledgers;
6. issue a short-lived X.509 client certificate bound to a SPIFFE identity,
   issue and install a short-lived OpenSSH user certificate, prove that the
   target `sshd` rejects the bare key, accepts the CA-signed principal, and
   rejects it after expiry; then apply and revoke the WireGuard peer.

PostgreSQL runs in the `authority-db` LXC container. Start the privileged
database agent first if it is not already running:

```sh
mise run agent:serve
```

In another terminal, start the complete PoC:

```sh
mise run poc:run
```

The runner discovers the running `authority-target` LXC address and client
WireGuard key automatically, installs the target agents, and waits for its
node identity endpoint before presenting the bootstrap URL.
Open the bootstrap URL printed by the runner. Use **Create user and Passkey**
once, then **Sign in with Passkey**. A successful run prints the local SSH key
and certificate paths together with the issued OpenSSH certificate. The page
also exposes a WebSocket-backed SSH terminal whose client process runs inside
the loopback-only Node Agent; the private key never enters browser JavaScript.
Installing the certificate requires a control-plane-signed node authorization,
and opening the terminal requires the matching browser-held random capability.
At expiry the Node Agent denies terminal reconnection; the E2E also connects
directly to prove that the target `sshd` rejects the expired certificate.
The terminal reaches `sshd` through the `authority-client` WireGuard data
plane, so removing the target peer also denies terminal reconnection.

### Revocation distribution

Revocation is a signed, target-scoped, protocol-independent decision notice.
Its affected adapter set can include SSH, WireGuard, and mTLS. The Control Plane
commits each notice to `policy.revocation_notices` before distribution and
assigns a monotonic sequence. The target Network Agent verifies the signature,
audience, node binding, and lifetime before removing an active peer. A notice
received before its Grant blocks that Grant from being installed later.

The Control Plane claims durable per-receiver delivery work with READ COMMITTED,
row locks and expiring ownership, then sends `POST /v1/revocations` to the target
Network Agent over the LXC underlay (`AUTHORITY_NETWORK_AGENT_ORIGIN`). Other CP
replicas can retry a crashed worker's claim. Proxies and redirects are disabled.
Each address identifies a kernel actuator. mTLS services instead subscribe with
independent process epochs, durable cursors and short enforcement leases; CRL and
OCSP responses come from the shared certificate ledger. See
[mTLS authority and revocation](docs/mtls-revocation.md) for configuration,
completion semantics and replication boundaries.
The UI reports persistence, not an acknowledgement from the enforcement agent.

Manual reconciliation can also read
`GET /v1/revocations?target_node_id=...&after=...` (Pull) and submit the same
signed envelope to the agent. Pull requires a session and a device proof for
`revocations.read`, binding the target UUID and cursor. It returns only notices
for that session's user and device; anonymous enumeration is rejected. The browser
helper `authorityPullRevocations(targetNodeId, after)` supplies these proofs.
Applying a notice twice is intentionally idempotent.
Kernel grant application reserves its replay nonce durably before mutation. A
reported kernel failure releases that reservation durably, allowing the same
grant to be retried; process crashes retain the reservation and fail closed.
Successful grants remain replay-protected across restarts.
The PoC UI exposes **Revoke current access**, and `mise run poc:e2e` proves
Push removal, Pull reconciliation, late-Grant rejection, and SSH-over-WireGuard
denial while the SSH certificate itself is still valid. It also issues a
longer-lived replacement network Grant and proves the inverse boundary: SSH
expiry does not remove WireGuard access, which remains active until its own
deadline.

### Selective TCP admission

TCP admission is a separate projection of the same policy decision, identified
as `tcp.port`. `POST /v1/tcp-authorizations` accepts the authenticated device and
target, sorted unique `destination_ports`, `ttl_seconds`, and `include_network`.
With `include_network: false`, it emits only `tcp_grant`: no peer, SSH, or mTLS
material is required or issued. With `true`, TCP and WireGuard grants share a
decision id but keep independent deadlines. All selection fields are bound into
the device proof (`access.authorize_tcp`).

The policy engine plans `tcp.connect` separately; selecting mesh membership also
requires `mesh.join` and `network.reach`. The winning TCP policy's `tcp_ports`
limits which ports may be requested. Existing policies default to no TCP ports;
the demo bootstrap explicitly permits 8080 and 8081. The signed TCP contract
binds subject, device, node, source IPv4 address, destination IPv4 address,
ports, audience, decision, and lifetime. Bootstrap reserves the configured
`AUTHORITY_TARGET_MESH_ADDRESS` (default `10.77.0.2`) to match the provisioned
PoC target; an address already owned by another identity is rejected.

After signing in, the **TCP access** section lets you select ports, lifetime,
and whether to also authorize WireGuard. The corresponding browser helpers are:

```js
const authorization = await authorityRequestTcpAuthorization([8080], true, 20);
// The UI installs network_grant (when selected) and tcp_grant at the target.
await authorityRevokeDecision(authorization.decision_id, ['tcp.port']);
```

The target Network Agent accepts `POST /v1/tcp-grants` and installs an atomic
nftables admission set with kernel timeouts. `AUTHORITY_TCP_MANAGED_PORTS`
(default `8080,8081`) defines the services governed by this adapter on `wg0`.
These ports deny TCP traffic until explicitly granted; other ports retain the
existing network/service policy. Filtering applies to both packet directions,
including established streams, without an established-connection bypass.
Overlapping grants for the same address/port tuple remain allowed until the
last independent grant expires or is revoked. Only the adapter's own
`inet authority_tcp` table is managed. The implementation uses the
[nftables set timeouts and concatenations](https://www.netfilter.org/projects/nftables/manpage.html).

`POST /v1/access-authorizations/{decision_id}/revocations` optionally selects
`adapter_kinds`; the selection is included in the `access.revoke` device proof.
Omitting it revokes all adapters issued by that decision. A `['tcp.port']`
notice removes only that decision's TCP admission, retaining its WireGuard peer
and grants from other decisions. Later `['wireguard.peer']` revocation has its
own durable sequence; repeating a scope returns its original notice. The
Control Plane delivers these notices directly over the management underlay.
Adapter-specific durable tombstones reject late grants across agent restarts;
restart clears active TCP admission, so it fails closed.

`mise run poc:e2e` installs two echo services with `mesh:tcp-demo:install` and
proves selected/unselected ports, TCP-only versus combined projection, proof
and grant tampering rejection, replay, selective revocation of both new and
established streams, late-grant denial, overlapping independent service access,
and TCP expiry while WireGuard remains active. Linux targets require nftables;
the LXC installer installs it before starting the Network Agent.

## Ability planning

Authorization now selects a realization from an ability/mechanism hypergraph
inside the effective policy envelope, then projects only its selected adapters.
The authorized plan binds identity, target, keys, ports, principals and independent
validity intervals; projection consumes these immutable scopes directly. Requested
leases cannot outlive their winning policies or configured TTL limits.
TCP requests can opt into automatic existing-route/mesh selection with
`automatic_route: true`; the browser helper accepts it as its fourth argument.
Existing-route availability requires the server's optional
`AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS` declaration. Planning choices, rejected
candidates, scoped permissions and dependencies are recorded in `access.plan`
and `policy.plan.evaluated` v2 within the authorization transaction. Policy reads,
scoped evaluation and all decision writes share one READ COMMITTED transaction with
shared locks on the policy/device/target rows; responses are returned after commit.
The graph separates direct credential/admission authority from derived usable
abilities. Trusted endpoint and route facts come from `device.nodes.endpoint_facts`;
new or upgraded nodes default to an empty manifest and fail closed until configured.
The PoC bootstrap declares its installed fixture environment. Audit v2 records the
complete derivation trace. Only the current planning format is accepted; there is
no legacy catalog or replay fallback.
See [Ability planning](docs/ability-planning.md) for the model, current access
integration, search bounds and scoped-ability migration.

## Testing without Passkey hardware

Chromium DevTools provides a software WebAuthn authenticator which still runs
the real browser WebAuthn ceremony:

1. open DevTools on the PoC page;
2. press `Ctrl+Shift+P`, enter `WebAuthn`, and select **Show WebAuthn**;
3. enable **Enable virtual authenticator environment**;
4. add an authenticator with protocol **CTAP2**, transport **internal**, and
   **Supports user verification** enabled;
5. return to the page and create the Passkey.

Keep that DevTools session open while registering and signing in so the same
virtual credential remains available.

## Connecting from another machine

The three PoC services bind to loopback on ports 3000, 3001, and 3002. They are
deliberately not exposed as plaintext HTTP services on the LAN: doing so would
leak bootstrap and session material, and a raw LAN origin is not a WebAuthn
secure context.

The browser-facing issuer and agents also reject cross-origin browser access
unless the exact origin appears in the comma-separated
`AUTHORITY_BROWSER_ORIGINS` setting. Wildcard origins are rejected. The LXC
network-agent deployment allows only the normal localhost PoC origin and the
dedicated browser-E2E origin.

For a browser running on another machine, forward all three ports and continue
to use the `localhost` URL:

```sh
ssh \
  -L 3000:127.0.0.1:3000 \
  -L 3001:127.0.0.1:3001 \
  -L 3002:127.0.0.1:3002 \
  <authority-machine-ip>
```

Then open the bootstrap `http://localhost:3000/#bootstrap=...` URL in the local
browser. A production-style LAN hostname requires HTTPS and matching
`AUTHORITY_RP_ID` / `AUTHORITY_RP_ORIGIN` values.

All private keys and bootstrap secrets are generated under `.secrets/`, which
is ignored by Git. Stop the PoC with `Ctrl-C`.

### SSH CA rotation

The PoC uses an explicit overlap window so an SSH CA can be changed without a
flag day. The previous private key is retained for recovery and is never
deleted automatically.

```sh
mise run ca:prepare
mise run ca:deploy-trust  # target trusts old + new
mise run ca:activate
# Restart poc:run so issuer and node-agent load the new active key/bundle.
# A directly-run issuer can instead reload the active private key with SIGHUP.
# Wait at least the maximum SSH certificate TTL before retiring the old CA.
mise run ca:finalize
mise run ca:deploy-trust  # target now trusts only the new CA
mise run ca:status
```

`ca:prepare` generates `.secrets/ssh-ca.next` and writes the old/new public
keys to `.secrets/ssh-trusted-user-cas.pub`. `ca:activate` moves the old key to
`.secrets/ssh-ca.previous` and makes the staged key active. Finalization only
changes the trust bundle; it deliberately keeps the previous private key for
an explicit, separately audited archival or destruction procedure.

Run the checks with:

```sh
mise run test
cargo clippy --workspace --all-targets -- -D warnings
```

With matching `chromium` and `chromedriver` packages installed, the browser
flow can be exercised headlessly with a WebDriver virtual authenticator:

```sh
mise run poc:e2e
```

Formal verification obligations, property tests and the revocation model are
tracked in [Verification](docs/verification.md). Run `mise run verification:pbt`
and `mise run verification:tla:mutations` (Java 11+). For the Verus proofs, run
`mise run verification:verus:setup` once, then `mise run verification:check`
for the combined proof/model/property gate.

A network-agent restart clears installed WireGuard/TCP state but retains consumed
replay nonces. Clients must obtain fresh authorization after restart; replaying an
unexpired grant does not reinstall it. Failed kernel operations remain retryable
within the same running process after their reservation is rolled back.

Authentication starts are public, but pending challenges and issuance rates are
bounded per user and challenge kind in the shared DB (4 pending challenges,
8 starts per 30 seconds).
Excess pending challenges evict only that user's oldest entries. Sessions are
limited to 8 per user; successful sign-in replaces only that user's oldest
sessions. Each domain admits at most 4096 sessions and 4096 pending challenges of each
kind. These limits isolate a single known account's resource usage across replicas;
network/IP-level throttling and protection against targeted account starvation
remain deployment responsibilities. Forwarded client-IP headers are not trusted
as an identity or rate-limit key by this PoC.
