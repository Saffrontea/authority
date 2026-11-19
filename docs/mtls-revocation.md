# mTLS decision revocation

mTLS revocation is enforced by the credential issuer and the Authority TLS service,
independently of WireGuard/TCP removal. A certificate's decision ID is its X509
common name. Its SANs contain the SPIFFE domain/user/device identity, service DNS
audience and `urn:authority:target:<node-id>`. The new service requires all three
bindings; legacy certificates without the target SAN are rejected and must be
reissued. Client certificates retain the exact authorized validity and client-auth
usage. The TLS acceptor requires a trusted client chain; session tickets and the
session cache are disabled.

## Issuance and service fences

`authority-mtls-core::AccessStore` serializes durable nonce consumption, mTLS
issuance and revocation under one mutex. Signature/key validation precedes the
issuance critical section. Its clock check, revocation check, nonce consumption
and actual CA signing execute within that critical section. A revocation received
before issuance therefore prevents signing even if the authorization has not yet
been consumed. A signing operation that preceded the revocation may finish, but
its certificate is rejected by the service fence.

A signed `mtls.client_certificate` notice is verified for the expected adapter and
target before mutation; the service also requires its configured domain. The
issuer can serve multiple signed domains/targets, with independently framed,
hashed tombstone keys. The durable record is synchronized before success or
session cancellation. Restart reloads the record before accepting requests.
Duplicate delivery remains idempotent. Notice retention uses the maximum recorded
adapter expiry, including mTLS, rather than only SSH/WG lifetimes.

The service checks certificate domain, target and service, then registers each
connection while holding the same lock as revocation. A revocation persists the
tombstone and cancels all matching sessions. Its HTTP receipt waits until each TLS
socket has been closed; a new handshake cannot register behind that fence. Other
decisions are unaffected. Existing sessions also have an independent certificate
expiry deadline, so HTTP keep-alive cannot bypass validity. The reference service
supports HTTP/1.1 `GET /whoami` on TLS port 8443 and bounds concurrent handshakes and
sessions. Cancellation discards any pending HTTP response and attempts bounded
TLS close-notify before closing the socket.

## Delivery and API semantics

The Control Plane routes WG/TCP notices to the network agent and mTLS notices to
both configured receivers. Background retry progress is keyed by notice sequence
**and destination**, so a network-agent ACK cannot mark mTLS delivered. mTLS
receipts must identify the adapter, decision and sequence; an empty HTTP 200,
redirect, failed request or stalled response does not count.

For an mTLS-containing revocation, the API persists the notice and synchronously
waits for the issuer fence and service-drain receipts before returning success.
A failure returns `503 mtls_revocation_pending`; the durable request remains and
the background dispatcher retries. Retrying publication returns the same signed
notice and rechecks enforcement. A partial delivery can already have revoked one
receiver despite the pending response. WG/TCP retain their existing asynchronous
delivery semantics. The configured PoC has one issuer and one target service;
additional replicas/targets require their own delivery destinations and receipts.

This is application enforcement of a signed decision, not a general PKI CRL/OCSP
service. An unrelated TLS service that only trusts the CA and never consumes these
notices will not enforce decision revocation. The guarantee concerns the Authority
service and configured issuer. It does not promise rollback of requests already
completed before the fence, arbitrary wall-clock discontinuities or power-loss
correctness beyond the underlying ledger's durability assumptions.

## Running and verification

`poc:run` builds the binaries first (and `poc:e2e` finishes this build before
starting its service readiness deadlines), starts the issuer, obtains the LXC target
identity, and installs `authority-mtls-service` in that target. The service has
separate HTTP management and TLS data listeners. Its server private key stays in
the LXC; only the public server certificate is exported for fixture trust. The
management origin remains independent of the WG route being revoked.

Control Plane configuration requires `AUTHORITY_CREDENTIAL_ISSUER_ORIGIN` and
`AUTHORITY_MTLS_SERVICE_ORIGIN`; the PoC scripts supply them. Standalone service
configuration is explicit in the generated systemd unit in
`deploy/lxc/authority-mesh.sh`. `mise run mesh:mtls:restart` restarts it without
clearing durable state.

Native tests exercise serialized issuance/revocation, authenticated notices,
ACK-after-session-drain, scope isolation, replay and ledger reopen. Generated
consumer traces interleave issue, register, revoke, close, malformed notice,
independent decision and restart; they are included in `verification:pbt` and
`verification:check`. Issuer PBT additionally checks that actual generated X509
material passes the service binding parser and rejects other domains/targets/services.

The LXC suite uses actual TLS client certificates over the target underlay, without
applying any WG grant for those decisions. It checks successful CA/binding
admission, new and existing connection revocation, unaffected independent
connections, revoked unconsumed issuance, duplicate notices, an actual service
restart, an isolated actual issuer process restart with the same ledger, and
certificate expiry on new and existing connections, and a stopped receiver
producing a pending response followed by background-delivery recovery. Fractional
wall-clock time is preserved when deriving monotonic expiry deadlines. Native delivery tests reject
incorrect receipts; the persistent dispatcher remains responsible for retry.

The database retention regression uses the production lookup against real
PostgreSQL with an mTLS adapter expiry later than the legacy transport bundle.
Run `AUTHORITY_DB_HOST=<host> cargo test -p authority-control-plane -- --ignored --test-threads=1`
to include it alongside the existing READ COMMITTED/row-lock/rollback and
unknown-capability regressions. All inserted retention fixtures are rolled back.

Validated with `PROPTEST_CASES=4096 mise run verification:check`, the three real
PostgreSQL regressions, targeted clippy with warnings denied, and both LXC route
modes (seeds 7 and 42). Both LXC runs passed the mTLS cases above as well as the
existing WG/TCP lifecycle replay and planning audit. The mTLS additions have
native/PBT and actual TLS evidence; this is not a universal refinement proof of
the issuer/service or its TLS/OS implementations.
