# Symbolic resources and identity revocation

## Resource algebra in the running authorization path

`contracts-model::resources` (re-exported by `policy-core`) represents a resource set as normalized disjoint
half-open integer intervals. Adjacent intervals merge. Empty sets are explicit;
empty intervals, overlapping/adjacent/out-of-order wire intervals and unknown
fields are rejected. IPv4 bounds use 64-bit integers so `/0` has the exact
exclusive upper bound 4294967296. Port zero is excluded by TCP selectors.
`IntervalSet::cidr` rejects host bits in a network address.

Union, intersection, difference and inclusion operate on intervals, never by
enumerating represented ports or addresses. A product `Region<N>` separates
resource axes and time. Exact product difference produces disjoint products;
subtracting unions has an explicit partition budget. Exhaustion returns an error
without a partial authorization result. The generic authorization algorithm
orders rules by priority, deny, then policy ID and subtracts winning regions.
Policy revisions are provenance only.

Production TCP policy evaluation and authority-union comparison use this algebra
for source/destination/port/time products. Symbolic stored selectors use `tcp_admission_range` and
`tcp_connection_range` with `source`, `destination`, and `ports` interval sets:

```json
{
  "kind": "tcp_connection_range",
  "source": [{"start": 167772160, "end": 184549376}],
  "destination": [{"start": 167772160, "end": 184549376}],
  "ports": [{"start": 1024, "end": 65536}]
}
```

Both address sets above represent 10.0.0.0/8. Policies retain their complete
symbolic region; evaluation subtracts precedence regions from the exact request.
A deny hole on any resource/time axis denies an incompletely covered request.
Bootstrap TCP policies use the same range selectors.

`Ipv4Set` and `PortSet` enforce resource-domain bounds and canonical wire encoding.
TCP requests accept interval arrays (`source_addresses` and `destination_addresses`
are optional and default to the attested hosts). `TcpAccessGrantV2.resources`
contains all three axes; signing, replay evidence and projection preserve them
exactly. Signed envelopes are V2 and require identity generations; old envelopes
are rejected. Raw SSH authorization is V2 and binds the common decision ID
independently of the terminal nonce.

The target's signed observation V2 includes the actual nft managed-port intervals.
A request outside that coverage is denied. The current managed target describes
one source/target host pair, so broad CIDRs require additional endpoint support
and are rejected by that adapter today. The resource algebra, wire format and
native nft compiler support CIDR intervals without enumerating addresses. nft
uses interval concatenations with timeouts; overlapping grants are partitioned
into disjoint products with the longest valid deadline. Fragment/operation and
kernel-element budgets fail the whole operation before nonce consumption. SSH
principals remain finite sets.

Executable property tests compare interval operations with independent bounded
pointwise oracles. Verus uses an explicitly trusted semantic set view for the
interval representation: it proves containment and exact projection field wiring,
not the interval implementation or Linux nft semantics.

## Live identity revocation

`contracts-model::fence` defines identity generation bindings and V3 signed
notices with tagged decision, subject or device selectors. Subject/device notices
carry the minimum accepted positive generation. Domain, target, reason, sequence,
delivery window and adapter selection enter the domain-separated preimage.
Adapters are sorted lexically for signing; duplicate adapters are rejected. Each
selector has an explicit tag and identity field. Independent Python-generated
golden vectors specify the binary encoding. `issuer-core::fence` authenticates
the signature and validates domain/target/adapter/time before acceptance.

`replay-ledger::fence::FenceStore` provides monotone durable subject/device fences.
It holds an exclusive process lock, rejects malformed/duplicate/cross-binding
snapshots, writes a new 0600 file, fsyncs it, renames it, and fsyncs the parent
directory before publishing a fence. Ambiguous write failure or capacity exhaustion poisons the instance
and rejects all grants until recovery. Fences do not expire. Older or repeated
delivery cannot lower a generation. A repeated fence must still trigger cleanup
retry; persistence success alone never acknowledges kernel cleanup.
Cleanup must test installations against the store's current fences, including
when an older notice is redelivered; the incoming minimum alone is insufficient.

`POST /v1/identity-revocations` accepts a root-signed V1 management command
(subject or device selector). A separate operator signing root is an explicit administrator trust
assumption. The control plane reads only `AUTHORITY_OPERATOR_PUBLIC_KEY_FILE`
and `AUTHORITY_OPERATOR_KEY_ID`; it rejects reuse of its grant signing key. `authority-admin`
signs a short-lived command using `AUTHORITY_OPERATOR_KEY_FILE`:

```sh
authority-admin http://localhost:3000 DOMAIN_UUID subject USER_UUID compromised
authority-admin http://localhost:3000 DOMAIN_UUID device DEVICE_UUID compromised
```

One READ COMMITTED transaction disables the identity, increments its generation,
marks matching grants/credentials revoked, and publishes signed V3 selector notices,
PKI events, audit and outbox. Authorization and SSH/mTLS redemption hold subject
then device shared row guards through commit; revocation takes the relevant
exclusive guard. The command nonce makes retries idempotent. Set
`AUTHORITY_OPERATION_NONCE` to retry/query a committed operation with the same
selector and reason. `completed` requires node-signed cleanup receipts bound to the complete notice,
verified against the enrolled node key, and current
mTLS instance acknowledgments (or expired enforcement leases), not publication alone.

Signed SSH, mTLS, WG and TCP envelopes carry the exact subject/device generations.
WG/TCP/SSH target fences persist before withdrawal and acknowledgment. SSH
certificates encode generation/decision/expiry metadata in their CA-signed key ID.
A root-only sshd principal command starts a systemd watchdog cgroup per connection;
the enforcer checks fresh observation, identity fences and decision tombstones on
admission and renewal. Revocation, expiry, agent stop or watchdog failure kills
that cgroup including descendants. Managed sshd disables PAM migration and static
principal/key bypasses. This needs Linux cgroup v2 and systemd; removing the guard
invalidates endpoint support.

The network agent has an independent systemd watchdog/stop helper to remove WG
peers and flush TCP allowances even on process failure. mTLS generation checks
share the issuer DB, while durable PKI events tear down each established replica
session and feed CRL/OCSP. The selector is the issuance fence; per-decision PKI
fanout supplies certificate/session cleanup rather than authorizing old grants.

Restart discards installed WG/TCP authority and keeps durable replay/fence state;
valid old consumed grants therefore require reauthorization. An explicit trusted
administrative reactivation advances generations again. Old sessions and unredeemed
grants remain invalid and a fresh passkey session is required. Scoped enrollment
and administration through the general ability policy remain future work.
