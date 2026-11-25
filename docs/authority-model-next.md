# Authority model: selection, observation, revocation and genesis

Status: partial implementation. Authority-order selection is implemented in this
iteration. Signed endpoint observations now drive the managed LXC access path;
see [implemented protocol and its limits](endpoint-observations.md). Selector
revocation, resource intervals and modeled enrollment remain **not yet live**.
The bootstrap token is still an external trust root. The target probe is trusted
software, not hardware-backed attestation or fully self-describing authority.

## Authority order and its limits

For a plan H, A(H) contains its complete authority closure: direct grants,
mandatory derived effects, and any preexisting authority actually seeded into the
plan. Define A <= B when every scoped permission in A is covered by the union of
permissions in B, including binding, resource and validity. Select a Pareto-minimal
feasible plan first, then use mechanism count and stable IDs for deterministic
selection among equivalent or incomparable minima. A strict dominator wins even
if it requires more mechanisms. An incomplete search never authorizes.

This is a preorder on representations, a partial order after quotienting by
mutual coverage. `contains` alone does not make the existing tagged union a
complete lattice: bottom, arbitrary unions and cross-kind implication are not
all representable as one `AbilityScope`. Mesh membership and TCP admission are
incomparable unless the catalog declares the relationship through explicit
mandatory effects. We do not invent privilege weights or infer a capability
from its OSI layer. A Pareto minimum need not be a least element or be unique.

The generic solver exposes the entire frontier. The current access catalog has
one scoped realization per route/outcome combination after mandatory effects;
deployment selection compares its replayable candidate plans. Adding alternative
realizations within a route must expose **all** incomparable local frontier plans
to global deployment selection, rather than discarding one by a local tie-break.
A regression must cover A || B, B < C, A || C where C uses fewer mechanisms: hiding
B would incorrectly admit dominated C. This is a catalog extension requirement,
not a claim that a single local representative solves arbitrary global search.

Native exhaustive-oracle properties cover the new frontier and semantic union
order. Existing Verus BFS proofs cover the mechanism-minimizing `solve` primitive;
they do not prove the new Pareto search or its ordering. The proof boundary must
be extended before claiming a formal least-authority guarantee.

## Signed, fresh environment observations

Replace the free-form fact array with a versioned signed node observation. Bind:

- domain and node ID, with verification against the currently registered key;
- CP-issued unpredictable challenge and intended verifier/audience;
- per-node monotone observation revision and boot instance;
- observed_at, expires_at, and the configuration generation/digests;
- typed facts with their concrete resource, CA/key fingerprint, service and probe
  identity. A bare `ssh_ca_trusted` boolean cannot distinguish the wrong CA.

The receiver verifies a domain-separated canonical preimage, registered active
node key and node ownership, audience, challenge, bounded clock skew and TTL,
strict revision progression, and every fact type. Unknown types, absent required
observations, expired observations and rollback fail closed. Challenge consumption
and observation persistence share one READ COMMITTED transaction, protected by
the node row lock; challenge generation/rate limits are also node-scoped and
durable across CP replicas. Refresh failure never extends the old expiry.
Authorization locks the observation with the policy/identity snapshot. A plan's
validity cannot exceed any supporting observation's expiry. Expiring or
superseding an observation invalidates the derived support, even if another
policy still permits the ability. Audit records retain the signed observation
revision/hash and concrete dependencies rather than re-reading current state.

The existing Network Agent identity signer can authenticate the target report.
Probe implementations must actually inspect the relevant enforcement boundary:
sshd's effective trust configuration for the named CA/principal/resource, the
running mTLS verifier's loaded CA generation, the installed nftables admission
rules and required hooks, and interface/route state for the concrete source and
destination. The route fact does not assert remote reachability. Config files
alone do not prove the running process loaded them. Reload failures withdraw the
corresponding fact. Reports originate at the target, not at the browser or CP.

A DB snapshot and its locks cover the persisted observation, not an atomic remote
kernel snapshot. A TTL is a bounded trust assumption, not proof that configuration
cannot drift before its deadline. The target must monitor changes and withdraw
support; dependent installations need expiry/revocation enforcement. Document the
residual detection/delivery window instead of claiming instantaneous attestation.

A node signature proves provenance, not truthful execution on a compromised node.
Initially the root assumption is an uncompromised target agent/probe and protected
identity key. Hardware-backed measured attestation, independent verifiers and
continuous drift detection are additional trust mechanisms, not properties of an
Ed25519 signature. No unsigned bootstrap fixture may silently replace a missing
report in the production decision path.

Acceptance: swapped node/domain/resource/CA reports, signature tampering,
challenge replay, stale/future times, key rotation, observation rollback,
withdrawn or missing facts, expired support, two-CP concurrent updates, process
restart and DB partition. LXC must change actual trust/rules and prove subsequent
authorization fails without relying on a manually updated fact flag.

## Subject and device revocation are issuance fences

Introduce a new notice/grant contract; do not overload decision IDs. The signed
selector is a tagged union of decision, subject, or device, always bound to a
domain and delivery target. Adapter kinds remain a separate bounded selector.
Subject/device identity generations are monotone and signed into issued grants;
a bulk notice advances the relevant minimum accepted generation. Compromise also
disables that subject/device's issuance. Re-enrollment requires an explicit
administrative action and a fresh generation; it never revives old grants.

Bulk revocation locks the identity generation row exclusively. Authorization and
credential redemption take the corresponding shared guard before reading it;
all follow the same domain -> subject -> device -> decision lock order. Existing
READ COMMITTED/advisory-lock rules remain applicable. Incrementing the fence,
disabling issuance, marking matching issued material and mTLS certificates
revoked, appending signed notices, and publishing delivery work commit together.
An issuance racing with this transaction must land wholly before the fence or
observe it and deny. Enumerating decisions for compatibility is not the fence.

Adapters retain subject/device/generation bindings in durable installation
metadata, persist the monotone fence before kernel cleanup, reject older queued
or replayed grants, and retry failed cleanup. Notice expiry never permits a
persistent fence rollback. Compaction is allowed only when no older signed grant
or credential can still be valid. mTLS CRL/OCSP and established-session fanout use
the same committed scope; each service process retains its own delivery/lease
obligation. Offline enforcement still needs bounded leases: a signature cannot
communicate a revocation across a partition.

Acceptance: every live decision for the selected subject/device is removed,
unrelated bindings remain active, old unredeemed grants cannot be installed,
post-compromise issuance is denied, concurrent issuance/rotation cannot cross the
fence, delayed delivery is safe, and two replicas/restart/partition preserve it.

## Symbolic resource algebra

Separate the permission algorithm from the current finite port/principal syntax.
The required resource-domain operations are empty, intersection, union,
difference, normalization and inclusion, with exact decidable semantics. Use
normalized disjoint half-open port intervals and IP prefix/interval sets. Keep
binding, operation/key identity, resources and time as explicit product factors.
Partition only at rule boundaries, never at every port or address. A CIDR /8 and
ports 1024-65535 must occupy bounded symbolic pieces rather than millions of
atoms. Unknown algebra variants fail closed.

Apply precedence to overlapping symbolic regions: higher priority first, deny
before allow at equal priority; policy revisions remain provenance, never a rank
across policies. The requested region minus permitted winning regions must be
empty. Differences of resource/time products may form multiple rectangles; the
representation must close over finite unions and impose an explicit partition
budget. Budget exhaustion denies, never approximates an uncovered region as
allowed. Schema, catalog matching, containment, evidence replay and projection
must all share this algebra. Current adapters may reject unsupported ranges or
compile bounded intervals to native nftables sets, without enumerating /8 hosts.

Acceptance: algebra identities and independent bounded pointwise oracles, holes
and adjacent intervals, overlapping priorities, mixed time/resource boundaries,
normalization invariance, large CIDR/range cases without point enumeration, and
partition-budget denial. The implemented finite union order is groundwork, not
an implementation of CIDR/range policy support.

## Explicit genesis and scoped enrollment

A trust root cannot authorize itself without an axiom or external trust anchor.
Make that axiom explicit: configured genesis public key, domain, validity, allowed
administrative operations and resources, immutable manifest digest, and audited
genesis grant. This is the boundary of the model, not an ordinary grant supposedly
proven by the same policies it creates.

Represent enrollment and administration as distinct scoped abilities: register a
node key, associate a device with a subject, install a bounded policy/delegation,
and activate enforcement configuration. Each request proves possession of an
appropriate signed administrative grant and traverses ordinary scoped policy
checks, constraint evaluation, nonce handling and audit transaction. Delegation
cannot exceed the root's domain, operation/resource set, validity or depth. A
policy-write ability must not imply arbitrary policy creation or arbitrary
reassignment. Observations remain target-signed evidence; enrollment cannot mint
live enforcement facts.

Retire `create_demo_access`'s omnipotent bootstrap token from the production
claim. Keep fixture setup explicitly privileged and outside the runtime path
until the genesis/enrollment contracts and administrative projections exist.
Acceptance includes tampered genesis manifests, cross-domain registration,
unauthorized reassignment, policy/delegation escalation, expiry/replay, rotated
root keys, and an audit linking every post-genesis administrative mutation to
its concrete authority.
