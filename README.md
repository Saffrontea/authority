# Authority PoC

This workspace demonstrates the initial end-to-end trust flow:

1. authenticate a human with a Passkey;
2. evaluate an explicit user, device, target, and principal policy;
3. verify proof of possession for both the browser device and the target
   node's LXC-held Ed25519 identity;
4. make one policy decision and bind both the SSH authorization and WireGuard
   grant to its shared signed decision nonce;
5. independently verify the scoped contracts in the Credential Issuer and
   target Network Agent, with durable replay ledgers;
6. issue and install a short-lived OpenSSH user certificate, prove that the
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

Revocation is a signed, target-scoped decision notice. The Control Plane
commits each notice to `policy.revocation_notices` before distribution and
assigns a monotonic sequence. The target Network Agent verifies the signature,
audience, node binding, and lifetime before removing an active peer. A notice
received before its Grant blocks that Grant from being installed later.

Immediate delivery uses `POST /v1/revocations` (Push). Reconciliation reads
`GET /v1/revocations?target_node_id=...&after=...` (Pull) and submits the same
signed envelope to the agent. Applying it twice is intentionally idempotent.
The PoC UI exposes **Revoke current access**, and `mise run poc:e2e` proves
Push removal, Pull reconciliation, late-Grant rejection, and SSH-over-WireGuard
denial while the SSH certificate itself is still valid.

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
