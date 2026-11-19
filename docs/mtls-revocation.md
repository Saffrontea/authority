# Shared mTLS authority and revocation

PostgreSQL is authoritative for client certificate issuance, consumed issuer
nonces, serial allocation, decision revocation, event delivery and process
membership. Control Plane replicas also share bootstrap consumption, server-side
WebAuthn challenges, sessions and device-proof nonces. Serialized WebAuthn state remains server-side and is atomically deleted
on consumption; it is never sent as client-held state. Only live sockets,
cancellation fences derived from committed events, immutable signing keys and
monotonic deadlines are local. Production issuance has no local-ledger fallback.

## Transactions and replicas

Authority mutations explicitly use READ COMMITTED. Issuance and revocation take
the same `(domain, target, decision)` row lock. Issuance checks DB time and
revocation, consumes the nonce, allocates a global sequence serial, signs and
inserts the certificate in one transaction. Nonce consumption is scoped to the
adapter type, independent of CA key rotation. Signing/storage failure rolls back
nonce consumption; unused sequence numbers may be skipped. Revocation records
the signed decision notice and marks every associated certificate revoked in the
same transaction as its audit/outbox records. Whichever operation acquires the
decision lock first establishes the ordering.

Publication holds the singleton revocation-stream row lock through commit.
Sequence order therefore follows publication commit order, avoiding a cursor
skipping a lower sequence whose transaction commits later. Each service process
registers a new UUID epoch, starts without a lease, reads committed events after
its durable cursor and acknowledges only a contiguous prefix after local sockets
have closed. An acknowledgement from one replica never completes another's work.
New or restarted instances catch up before acquiring a lease.

Each lease lasts five seconds in DB time. The service uses a conservative
monotonic deadline measured **before** the renewal request. A renewal checks the
stream under a shared row lock and grants a lease only when caught up. Failure
or partition cannot extend authority. Existing HTTP connections close by the
lease deadline or certificate expiry, whichever comes first. TLS shutdown cannot
extend the lease. Admission additionally checks the certificate's known, active
serial in the shared DB and requires a current local lease. Local registration
and cancellation share a lock, preventing admission behind an applied event.
Session tickets and TLS session caching are disabled.

This assumes a trustworthy shared primary, bounded clock drift and a functioning
OS/runtime timer. PostgreSQL replication/failover must preserve committed writes
and prevent split-brain primaries; asynchronous failover that loses a committed
revocation is outside this guarantee. Stopping a process stops its enforcement
work; after resumption the deadline is checked before polling HTTP work.

WG/TCP delivery uses durable per-receiver work rows with transactional
`FOR UPDATE SKIP LOCKED` claims and expiring ownership. CP replicas may retry a
crashed worker's claim. A network-agent address identifies the specific kernel
actuator for a target, not an arbitrary replica behind a load balancer. The kernel
actuator itself is not made active-active by this change.

## Standard X.509 interfaces

Certificates carry CRL Distribution Points and OCSP AIA URLs under the configured
`AUTHORITY_PKI_PUBLIC_ORIGIN`:

- `GET /v1/pki/{ca_id}/crl`: DER, `application/pkix-crl`.
- `POST /v1/pki/{ca_id}/ocsp`: DER OCSP request/response.
- `GET /v1/pki/{ca_id}/ocsp/{base64-request}`: the same OCSP responder.

Both responders read the shared certificate ledger. CRLs have CA signatures,
monotonically allocated CRL numbers, thisUpdate and nextUpdate. OCSP verifies
issuer-name/key hashes, returns good/revoked/unknown, echoes valid nonces, and
signs responses with the issuing CA. Responses have a 30-second validity window;
unknown serials or other issuers do not become good. SHA-1 and SHA-256 CertIDs are
supported. The implementation uses typed ASN.1 and OpenSSL signing, with no
external signing command or curl dependency.

The reference service fetches a bounded fresh CRL for each handshake and enables
OpenSSL `CRL_CHECK`, which checks its signature and validity. Fetch failure fails
closed. The temporary CRL file is derived verification input, immediately removed;
it stores no authoritative state. The additional DB admission check provides a
current fence even when a signed CRL from just before revocation remains valid.
External consumers must configure CRL or OCSP verification and enforce freshness;
trusting the CA alone does not enforce revocation. Their cache window can delay
recognition of a newly committed revocation. CRL/OCSP do not close already-open
TLS sessions; the per-process event subscription and leases do that.

Certificate identity still requires the SPIFFE domain/user/device URI, target
URN and service DNS SAN. The common name binds the decision. Existing certificates
missing those bindings or absent from the new shared ledger must be reissued.

## API completion semantics

`POST /v1/access-authorizations/{decision}/revocations` returns the persisted
signed notice after **commit**. It does not wait for all sockets. Repeating the
same scope returns that notice idempotently. Issuers immediately observe the DB
fence, including unconsumed authorizations.

`GET /v1/access-authorizations/{decision}/revocations/status` requires a fresh
owner device proof with action `access.revoke_status` and binding `[decision]`.
It reports `committed`, `mtls_sessions_drained` and per-notice status. Publication
snapshots every service epoch with a live lease. Drain completes when each has
acknowledged closure or its captured lease expires. A partitioned instance cannot
renew past a pending event and is not counted complete while that lease remains
live. Network delivery status is separate from this mTLS-specific drain field.
Already-completed application requests cannot be undone by revocation.

## Configuration and verification

Apply migrations before starting replicas. All participants require explicit
`AUTHORITY_DB_HOST` and `AUTHORITY_DB_PASSWORD_FILE` (or `AUTHORITY_DB_PASSWORD`);
port, name, user and SSL mode are configurable. The LXC development network uses
SSL mode disable. Production deployments should configure authenticated DB TLS
and protect service DB credentials. The service unit provisions its password as a
root-only file. No credentials are included in API responses.

Provision the same CP signing key/trust and issuer CA secret material on every
replica. Private keys stay in secret files, not the certificate ledger. The shared
`mtls-client` CA slot is immutable and rejects a differently configured issuer;
CA key/certificate matching is checked on load. PoC scripts generate initial key
files sequentially, then start the peer replicas using the same files. CA rotation
requires explicit trust and slot migration; automated CA rotation is not provided.

`poc:e2e` runs two CPs and two issuers behind round-robin ingress without session
affinity, and two actual LXC service processes on TLS ports 8443/8444. It exercises
cross-replica login, issuer nonce replay rejection, both services' established
connection revocation, restart, expiry and stopped-receiver lease completion.
A per-service DB fault proxy also severs already-open DB sockets for one replica
while its peer keeps running, verifying lease-bound drain and recovery. OpenSSL
CLI checks provide independent CRL/OCSP signature/status, nonce-replay rejection
and CRL expiry evidence. The CLI is a test dependency, not the production HTTP/signing transport.

Run the real DB regressions with explicit development DB configuration:

```
cargo test -p authority-mtls-core database::tests -- --ignored --test-threads=1
cargo test -p authority-control-plane -- --ignored --test-threads=1
```

The first uses independent pools to check global nonce consumption/serials,
signing rollback, issuance blocked behind a revocation row lock, contiguous
receipts and restart catch-up. Existing native consumer traces using file ledgers
are compiled only with the `test-support` feature (enabled for issuer tests)
and remain crypto/legacy fixture tests; they do not establish replica correctness.
`PROPTEST_CASES=4096 mise run verification:check` retains the solver proofs,
mutation checks and model/trace tests. These and actual LXC tests are evidence for
the stated boundaries, not a universal TLS/OS or distributed refinement proof.

Protocol references: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280),
[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960), and the updated nonce limits in
[RFC 9654](https://www.rfc-editor.org/rfc/rfc9654).

Validation for this change: the shared-DB tests (2), Control Plane DB regressions
(4), Control Plane native tests (9), workspace clippy with warnings denied, and
the full verification gate with `PROPTEST_CASES=4096` pass. Both LXC route modes passed: default route with seed 7 and existing route with
seed 42. Long-running proof jobs now report each verification
start and completion without buffered output.
