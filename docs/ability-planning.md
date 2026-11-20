# Ability planning

The authorization problem is to find a realization H such that:

- H realizes the requested intent.
- Every effective ability of H belongs to the request's policy envelope.
- H satisfies the request's constraints.

The policy envelope is evaluated for the authenticated subject, device, target,
domain and evaluation time. A mechanism is an implementation choice; an ability
describes the authority it provides. Issuing a credential is not itself the
effective ability of using that credential.

## Boundaries

`authority-planning-core` implements a finite, monotone directed hypergraph. It
has no knowledge of SSH, WireGuard, storage, identity providers or contract formats.
The caller supplies a fully scoped ability type and mechanism IDs:

```text
Mechanism: all prerequisite abilities -> all provided abilities
Derivation: all prerequisite abilities -> all mandatory derived abilities
```

Alternative mechanisms may provide the same goal. A mechanism is executable only
after all its prerequisites are available. Derivation rules run to a fixed point
after each step, so combined effects cannot be excluded to evade policy. Cycles
without an available starting point cannot bootstrap authority.

The solver checks the entire ability closure against the permitted set, including
side effects and preexisting abilities used by the plan. Existing abilities must
already be authorized; unauthenticated assertions and identity facts are not
abilities to seed into the solver. Solver permission inclusion is exact set
inclusion. The access integration normalizes scope containment into the finite set
of requested scoped abilities before solving. It does not enumerate every port or
every timestamp as a separate graph node.

The solver selects the fewest mechanisms and breaks ties deterministically by
mechanism ID and executable order. This is not an ordering of privilege: a broader
allowed plan may use fewer mechanisms. Final constraint predicates may depend on
the selected mechanism set and abilities, but not their execution order. Mechanism
exclusions and maximum plan size are also supported. Exhausting the explicit search
budget returns an error, never an allow decision. Search is exponential in the
worst case; each solve over the bounded access catalog retains a
32-state budget. Deployment selection evaluates at most two candidate catalogs.

Models must declare complete effects. The solver proves properties of that model;
it cannot discover capabilities an adapter exposes but its catalog omits. Models
are trusted application definitions, not supplied by the requesting client.
Only monotone effects are supported. Deletions, runtime enforcement success, and
mutable external facts require other validation or a richer transition model.

## Current access integration

The current catalog distinguishes direct authority from its usable effect:

| Mechanism | Direct authority | Mandatory derived authority | Trusted environment |
| --- | --- | --- | --- |
| WireGuard peer grant | Mesh membership and network route authorization | Network reachability | Mesh route configured |
| Existing route reuse | Network route authorization | Network reachability | Existing route configured |
| SSH certificate | SSH credential | SSH session authority | Target trusts the configured SSH CA; route prerequisite |
| mTLS certificate | mTLS credential | Service identity authority | Target trusts the configured mTLS CA; route prerequisite |
| TCP admission | TCP admission authority | TCP connection authority | Target enforces admission; route prerequisite |

For mesh plans, usable SSH/mTLS/TCP authority requires **both** its direct
credential/admission authority and network reachability. For direct plans it
requires the explicit `existing_route_configured` environment fact. WireGuard
provides membership and route authorization in one real grant: the mesh catalog
no longer counts a separate `NetworkRoute` step with no projection. Direct plans
reuse an external route and do not select a WireGuard peer. These are nine distinct
scoped authority kinds; direct and derived kinds cannot contain one another.

OSI describes the network/transport dimensions; identity and application remain
separate dimensions. A layer label alone never introduces a derivation. Legacy
policy vocabulary remains accepted: each winning permission explicitly covers
its corresponding direct and effective authority, with identical scope limits.
Unknown capabilities or endpoint facts are rejected, not discarded.

`ConditionalModel` adds environment guards to mechanisms and derivations. Its
`instantiate` method accepts a trusted immutable fact snapshot and produces the
ordinary finite model consumed by the existing solver. Facts never enter the
ability set, grant permissions, or satisfy authority prerequisites themselves.
The conditional catalog currently uses `ssh_ca_trusted`, `mtls_ca_trusted`,
`tcp_enforcement`, `mesh_route_configured`, and `existing_route_configured`.

Production reads these operator-declared facts from `device.nodes.endpoint_facts`
in the same locked READ COMMITTED snapshot as policy and target metadata. They
are not request fields. The default is an empty manifest, so an upgraded node
requires explicit configuration before usable authority can be derived. The PoC's
privileged bootstrap declares its installed fixture configuration. These are
configuration assertions, not live probes or automatic discovery of CA trust;
operators must keep them consistent with deployment changes.

Every derived output retains the direct input's subject/device/domain/target,
key, audience, principal/port set and validity. All authorization prerequisites
must cover the entire derived interval. A shorter transport lease therefore
rejects a longer usable-authority request, without silently shortening it.
Credential and transport expiration/revocation remain independently enforced.

`explain` independently replays executable steps and complete mandatory closure,
recording each derivation and the step after which its prerequisites exist. It
rejects invented, omitted and ungrounded effects. Production verifies this evidence
before returning an immutable authorized plan; projection emits material from
direct authority nodes only, avoiding duplicate or substituted credentials.

Planning evidence v2 records both kinds and the grounded derivation trace, plus
the environment snapshot. Replay checks the complete catalog-level closure as
well as scoped edges: omitting an output cannot disable the very rule that would
have produced it. Only the current v2 format and catalog are supported. Environment
and derivation fields are required; old and unknown versions fail closed. The PoC
does not retain a legacy replay path.

`policy-core::scoped::evaluate_scoped` first resolves existing policy precedence
and identity checks, then instantiates scoped abilities and the access catalog.
An ability carries the domain, subject, device and target plus:

- TCP: source/destination IPv4 addresses and the exact requested port set.
- SSH: the key fingerprint, selected principals and terminal token binding.
- Mesh membership: the registered WireGuard key and assigned IPv4 address.
- Network reachability: source/destination IPv4 addresses.
- mTLS identity: client SPKI hash, subject/device-derived SPIFFE identity and the
  trusted deployment's service audience. This is identity authority, not arbitrary
  application-operation permission.

Each also carries its independent `[not_before, expires_at)` validity interval.
A policy grant contains a requested ability only when all identity/resource/key
bindings match, its principal or port set includes the requested set, and its time
interval contains the entire requested interval. Empty principals, empty TCP port
sets, port zero and invalid intervals are rejected. Stored key selectors explicitly
choose request-bound possession or a pinned key. Selected keys are frozen into
the authorized plan.

Production reads `policy.ability_policies`, whose JSON selectors distinguish all
nine direct and derived authority kinds. Selectors bind resources, TCP port sets,
SSH principal sets and mTLS service audiences. Unknown kinds, unknown fields,
invalid scopes, effects or revisions refuse the whole snapshot as `invalid_policy`,
including malformed inactive deny rows. Existing capability-policy rows are not
converted or consulted by production. The capability evaluator remains a separate
coarse model used by its own tests.

For each requested ability, policy precedence is resolved independently for every
port/principal and every interval between policy boundaries: highest priority,
then deny over allow, then policy ID. Revisions identify versions of a single
policy and are never compared across policies. All requested atoms and time segments
must be allowed. Multiple rules can cover disjoint scope or time segments. A deny
on one port cannot silently disappear behind a broad allow. Direct permission
does not grant the corresponding derived authority. The entire graph is compiled
before permission filtering, preserving forbidden mandatory effects for rejection.

Every requested adapter lease must fit both the configured TTL limit and its
covering policies' validity intervals. Exceeding either is rejected, not silently shortened.
Integer timestamp conversion rounds policy starts up and policy deadlines down.
Zero, negative and overflowing lifetimes fail closed. Adapter leases remain
independent; expiry of an SSH or TCP lease does not change a separate mesh lease.
The graph models scoped usable authority at authorization time, not a guarantee
that runtime transport or an endpoint remains live for an entire lease.

The result contains an immutable `AuthorizedPlan`. Its bindings, material, scoped
abilities, intervals and policy provenance are private; callers can inspect them
but cannot rewrite them. Both production authorization endpoints pass this plan to
`projection-core::project_authorized`. Projection takes no replacement ports,
principals, keys or TTLs. It rejects mismatches in common claim identity, issuer,
policy provenance or issuance time before emitting unsigned contracts. It then
materializes only the selected mechanisms. `NetworkRoute` emits no contract.

The existing HTTP request shapes and signed contract formats remain compatible.
TCP input syntax and device proof checks remain at the API boundary; authoritative
port inclusion is in policy-core. `wireguard_key_mismatch` and `tcp_port_denied`
response codes are preserved. The unscoped `evaluate`/`realize` and low-level
`project`/`project_plan` APIs remain for compatibility and model tests; they are not
the production signing path.

## Deployment selection

`policy-core::selection::evaluate_selection` evaluates each available deployment
implementation against the same immutable policy snapshot and scoped inputs. It
then chooses the authorized plan with the fewest mechanisms, breaking ties by
candidate ID. An unavailable or rejected implementation cannot abort another
valid candidate. Availability is a deployment fact, never an authorization grant;
all selected abilities still have to pass scoped policy evaluation.

The initial implementations are:

- `existing_route`: issue the selected service admission/credentials and reuse an
  externally provided transport. No mesh membership is granted.
- `wireguard_mesh`: explicitly authorize and project a WireGuard peer plus the
  requested service admission/credentials and their dependency closure.

These are complete alternative implementations using the existing adapters. This
version does not combine different transport choices per service in a hybrid plan.
It also does not infer that a network path exists from a client's request. Exact
route selections never fall back and still require their explicit trusted route
configuration fact. An exact choice that contradicts the request is rejected.

The TCP endpoint supports explicit opt-in with `automatic_route: true`. It cannot
be combined with `include_network: true`, which remains a mandatory mesh request.
Absent/false `automatic_route` preserves the legacy request and device-proof format.
True adds an `automatic` binding to the signed device proof, so changing the mode
invalidates that proof. The browser helper's optional fourth argument selects it:

```js
await authorityRequestTcpAuthorization([8080], false, 20, true);
```

By default automatic selection considers the configured target's mesh route only.
Setting `AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS` declares an existing route from
that IPv4 source to `AUTHORITY_TARGET_MESH_ADDRESS`, for the configured client
WireGuard public key. The declaration must match the requesting device's assigned
source, registered key and target address. A mesh candidate must match the
configured mesh target. These are trusted deployment declarations, not live
reachability probes, discoveries of active peers, or mechanisms for bypassing
network policy. The legacy TCP-only request format is unchanged; its target must now explicitly
declare an existing route and TCP enforcement.

## Authorization transaction

Both authorization endpoints begin one `READ COMMITTED` PostgreSQL transaction
before loading policy. The policy loader requires that transaction, rather than a
pool. It acquires a shared transaction advisory lock keyed by domain, subject and
target before reading policies. A database trigger acquires the exclusive version
of that same lock on every policy insert, update and delete, including changes to
the scope key. Writers moving a rule acquire both keys in numeric order. This
prevents new deny rows from appearing between policy evaluation and issuance.
The requesting device, target node and target device are locked with `FOR SHARE`. Policy evaluation, scoped planning, local signing, decision
persistence, audit and outbox writes all occur before that transaction commits.
Persistence helpers borrow it and receive scalar context instead of an application
state/pool; they cannot independently commit the authorization.

Allow responses are returned only after commit. Policy denials also commit their
audit/evidence in that same transaction before returning a denial response. Any
projection/persistence/commit failure returns no grant. Deadlocks return
`503 authorization_conflict`; a retry needs a fresh device proof.
There is no reuse of a previously evaluated decision after a conflict.

Policy rows use the advisory guard and ordinary MVCC reads, avoiding a policy
row-lock/advisory-lock ordering cycle. The guard lasts through issuance, audit and
commit. Later policy changes do not retroactively revoke already issued contracts;
dependent invalidation remains a separate integration.

The LXC concurrency regression checks the isolation level, observes real blocked
writers through `pg_stat_activity` for policy/device/node changes and deny insertion, and forces an
outbox constraint error after audit/evidence writes. Separate connections cannot
see an uncommitted decision, and rollback leaves neither audit nor outbox records.
The writer's test changes are themselves rolled back.

## Shared definitions

### Issuance provenance

`policy.issued_ability_grants` stores the concrete binding, scope, validity and
winning policy references for newly issued mesh membership, SSH credentials,
mTLS credentials and TCP admission. Only direct material provided by an executed
step is recorded; derived effects and reused inputs do not become newly issued
grants. These rows commit with the signed authorization's audit and outbox.
An outbox failure rolls back the grant records as well.

Publishing a signed revocation updates the matching ledger rows in the same
transaction. Domain, target, decision and adapter scope constrain the update;
revoking a WireGuard peer does not revoke an independent TCP admission record.
Revoking the SSH terminal capability invalidates the corresponding combined SSH
credential scope too, because that scope binds the terminal token.

These are issuance records, not installation receipts. They do not seed the
solver. Authenticated target observations, revision/epoch tracking and dependent
invalidation still need to be connected before enabling reuse. Current DB
regressions cover issuance/audit/outbox rollback, revocation visibility and
adapter-specific invalidation.

`contracts-model::protocol` owns wire audiences, lifetime/port bounds and v1
planning-evidence bounds. Producers, verifiers, projection and policy scope checks
reuse them, and conformance tests compare the numeric bounds with the immutable
schema artifacts. Policy-core derives its exhaustive search budget from the plan
bound, and `AccessBinding::identity_uri` owns subject/device identity formatting.
Domain issuer formatting also has one definition in the protocol module. Deployment
TTL defaults and the demo audience belong to the Control Plane configuration;
unrelated timeouts and key sizes are not merged merely because numbers coincide.
The generic planning engine remains independent of protocol/storage adapters.

## Planning audit

Completed authorizations and policy-planning denials write an `access.plan` audit record and a
`policy.plan.evaluated` v2 outbox event inside the same authorization transaction.
A storage or evidence-validation failure aborts that transaction. The existing
`policy.decision.evaluated` v1 event and signed adapter contracts are unchanged.
Its concrete evaluated intent describes the selected candidate; the new planning
event separately records the original exact/automatic selection mode.

The new [contract artifact](../contracts/artifacts/policy-plan-evaluated-v2.schema.json)
contains the decision/attempt ID and versioned planning evidence:

- Authenticated domain, subject, device, target, evaluation time and outcomes.
- Concrete resource bindings and the deployment declarations evaluated at that time.
- Each candidate's mechanism count or stable rejection reason and capability.
- The selected candidate and deterministic selection rule.
- The selected scoped abilities, their containing effective permissions and the
  winning policy IDs/revisions.
- Goal indices, executable steps, environment facts, and grounded derivations
  with prerequisite/provided ability indices.

Successful events use the signed authorization's decision ID. Denials receive an
attempt ID and contain candidate reasons without a fabricated successful plan.
`PlanningEvidence::is_consistent` replays the recorded dependencies, checks scope
containment and resource bindings, and verifies candidate availability and the
selection rule before persistence. This checks the record's structural consistency;
it does not reauthorize against current policy, prove the historical winner from
an entire policy snapshot, or guarantee runtime transport availability. Deserializing
planning evidence cannot construct the immutable `AuthorizedPlan` accepted by
production projection.

## Next extension

Persist authenticated enforcement observations and seed the solver with live roots;
record their provenance in replay evidence, project only new grants, and publish
dependent invalidations atomically. Environment declarations still need persisted
source/revision/expiry metadata. Wildcard resources, CIDR containment, dynamic route
discovery and mixed per-service routing are not modeled.

## Validation

### Concrete permission and live-support primitives

`policy_core::ability_policy::authorize` evaluates concrete `ScopedAbility`
rules independently for direct and derived authority. It splits port/principal
sets and the requested interval at rule boundaries, then selects a winner for
every atom and segment by priority, deny precedence and policy ID. Every
segment must be allowed. Evidence includes all winning policy references;
disjoint rules can cover a request without hiding a narrow deny. Bindings,
keys, resources and authority kinds must match through scoped containment.

`planning_core::support::recompute` accepts authenticated observations of roots
and environment facts, with owner, source, current revision, revocation and a
half-open validity interval. It recomputes the least fixed point from remaining
live roots. Alternative roots preserve authority; cycles cannot preserve it after
the last independent root disappears. Mechanisms do not run during recomputation.
Mandatory effects are retained even when forbidden, so the solver can reject the
complete closure rather than silently dropping an unauthorized effect.

Concrete ability policies are connected to the production DB, planner and audit.
The `policy.decision.evaluated` event now uses the v2 ability-source contract;
planning v2 records every winning policy reference per ability. Signed `policy_id`
fields contain a domain-separated SHA-256 commitment to the canonical policy
reference set, keeping the wire identifier bounded for any number of rules. Grants and adapter
signing protocols retain their existing independent formats.

Live-support recomputation remains a core API: production still seeds planning
with an empty available set. An issued contract alone is insufficient evidence
that a target installed a network grant. The next integration must authenticate
and persist those observations before enabling reuse or dependent invalidation.

Production error propagation now distinguishes `planning_search_limit` and
`invalid_planning_catalog` from `no_authorized_realization`. All three fail closed;
budget exhaustion is not evidence that no solution exists.

Planner tests cover alternative routes, unauthorized side effects, mandatory
composition closure, multi-input dependencies, cycles, scoped identity/resource
separation, final constraints, deterministic ordering and budget failures. A
property test compares the solver's answer and minimum mechanism count against
independent exhaustive subset enumeration. Existing policy properties continue to
check dependency closure, deny precedence and rule-order invariance. Projection
tests cover TCP-only selection, required dependencies and compatibility with the
existing infrastructure contracts. Scoped tests cover winning-policy isolation,
port/principal containment, policy expiry, configured limits, invalid lifetimes,
identity/resource separation and independent adapter deadlines. Projection tests
verify that mutation of the original request cannot change the authorized output
and that claim rebinding is rejected.

Selection tests cover authorization-independent availability, binding mismatches,
policy/TTL rejection of one candidate, exact-route constraints and automatic
fallback. Provider conformance tests replay the new event vectors and reject scope
expansion, invalid dependency order and inconsistent selection. API tests verify
that automatic mode changes the device proof, and projection tests verify that
only the chosen implementation's material is emitted.

The LXC/browser suite exercises automatic planning with real nftables admission,
mode-proof tampering and selective revocation. Run both deployment configurations:

```sh
mise run poc:e2e
AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS=10.77.0.1 mise run poc:e2e
```

Each run finishes with `db:verify-planning`: a read-only PostgreSQL check of the
latest test actor's allow/deny/automatic audit coverage, identical audit/outbox
payloads, selected-plan/issuance correlation and exact TCP port/address/expiry
agreement. It also matches the issuance ledger to executed step outputs and
policy references, and checks its revocation flags against committed notices.
It can also be invoked separately after the suite. The reconnect fixture
resets only the PoC client's cached WireGuard transport after a revoked peer is
re-authorized; it does not alter the target agent's granted membership or TCP rules.

The strict stored-ability-policy decoder also has a read-only LXC PostgreSQL regression
that constructs typed rows without modifying stored policies. It verifies that a
valid allow and an invalid ability selector in a deny cannot yield a partial snapshot, in either order:

```sh
AUTHORITY_DB_HOST=$(mise run db:status | awk '/^ip: / { print $2 }') \
  cargo test -p authority-control-plane stored_ability_policies_fail_closed_in_postgres -- --ignored
```

It uses the local development credential file (or `AUTHORITY_DB_PASSWORD` /
`AUTHORITY_DB_PASSWORD_FILE`) and is explicitly opt-in outside LXC environments.

The transaction regression uses the same LXC development credentials as the decoder
test and a demo policy bootstrapped by `poc:e2e`:

```sh
AUTHORITY_DB_HOST=$(mise run db:status | awk '/^ip: / { print $2 }') \
  cargo test -p authority-control-plane authorization_transaction_locks_and_rolls_back_in_postgres -- --ignored
```

The derived-authority catalog is validated by the full verification gate with
`PROPTEST_CASES=4096`, 38 expected-failure proof mutations, nine-kind atomic
containment checks, real PostgreSQL regressions, and LXC route modes with
seeds 7 (mesh/default deployment) and 42 (existing-route deployment). Both live
runs verify v2 audit/outbox agreement with the actually issued TCP scopes. The DB
regressions additionally check endpoint-manifest row locking and fail-closed
handling of missing or unknown environment facts. Workspace clippy passes with
warnings denied.
