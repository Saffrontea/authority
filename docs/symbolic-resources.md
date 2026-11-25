# Symbolic resources and identity fence primitives

## Resource algebra in the running authorization path

`policy-core::resources` represents a resource set as normalized disjoint
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
for port/time regions. Symbolic stored selectors use `tcp_admission_range` and
`tcp_connection_range` with `source`, `destination`, and `ports` interval sets:

```json
{
  "kind": "tcp_connection_range",
  "source": [{"start": 167772160, "end": 184549376}],
  "destination": [{"start": 167772160, "end": 184549376}],
  "ports": [{"start": 1024, "end": 65536}]
}
```

Both address sets above represent 10.0.0.0/8. Resolution intersects this selector
with the concrete requested addresses and ports. Deny selectors retain their
intersection, including a hole affecting only part of the request. Resolution
never grants the entire broad policy range. Bootstrap's TCP policies use range
selectors too, so the ordinary LXC flow exercises their production decoding,
evaluation, evidence and projection.

Current request/grant contracts still accept a single source/destination and at
most 64 explicit ports. Their adapter restrictions remain explicit: range
policies do not expand the wire grant or enumerate a CIDR. A fully symbolic
requested `AbilityScope` and native interval projection are still future work;
the generic region API already accepts large symbolic requests. SSH principal
sets continue to use their finite resource representation. New algebra is tested
against independent bounded pointwise oracles, not covered by the existing Verus
proofs.

## Selector revocation primitives, not yet a live bulk-revocation API

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

These primitives are **not connected to production issuance or adapters yet**.
Existing grants have no signed identity generation and production revocation
remains decision-scoped. A complete integration must add generations to grants,
shared/exclusive DB issuance fences, a scoped API and transactional outbox, durable
receiver enforcement, credential-redemption checks and established-session
withdrawal. In particular, these definitions alone do not prevent redemption of
an old SSH authorization. See [the remaining acceptance requirements](authority-model-next.md).
