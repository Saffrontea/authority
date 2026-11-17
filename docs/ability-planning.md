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
worst case; each solve over the current five-mechanism access catalog has a
32-state budget. Deployment selection evaluates at most two candidate catalogs.

Models must declare complete effects. The solver proves properties of that model;
it cannot discover capabilities an adapter exposes but its catalog omits. Models
are trusted application definitions, not supplied by the requesting client.
Only monotone effects are supported. Deletions, runtime enforcement success, and
mutable external facts require other validation or a richer transition model.

## Current access integration

`policy-core::realization` owns the initial access catalog and separates abilities
from the legacy policy capability vocabulary:

| Ability | Dimension | Mechanism | Existing permission |
| --- | --- | --- | --- |
| Mesh membership | Network | WireGuard peer | `mesh.join` |
| Network reachability | Network | Network route | `network.reach` |
| SSH session | Application | SSH certificate | `ssh.issue` |
| Service identity | Identity | mTLS certificate | `mtls.issue` |
| TCP connection | Transport | TCP admission | `tcp.connect` |

OSI informs the network and transport dimensions. Identity is kept explicit,
rather than assigning it an artificial OSI layer. These dimensions are descriptive
metadata; sharing a layer never creates an implication between abilities.

Mesh-required service mechanisms depend on network reachability, which depends
on mesh membership. Direct requests retain the existing API assumption that the
route is externally available. A TCP-only request does not create mesh membership.
This catalog preserves the current intent semantics. Deployment selection can
compare the existing-route and WireGuard implementations; other protocols are
not assumed to be interchangeable.

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
sets, port zero and invalid intervals are rejected. The current policy vocabulary
permits the authenticated device to select SSH and mTLS public keys; those selected
keys are frozen into the authorized plan, not granted as an unbound wildcard.

Stored capability decoding is atomic and strict for both allow and deny rules.
The accepted vocabulary is `ssh.issue`, `mesh.join`, `network.reach`, `mtls.issue`
and `tcp.connect`, plus the explicit legacy aliases `ssh` and `wireguard` (the
latter expands to mesh join and network reach). Unknown strings, wildcard spelling,
case/whitespace variants and empty lists never produce partial or empty grants.
If any policy row loaded for the request contains invalid capability vocabulary,
the whole authorization is refused and audited as `invalid_policy`; the HTTP
response remains `policy_denied`. This conservative check includes inactive rows
returned by the policy lookup, so malformed stored configuration must be corrected
rather than relying on rule ordering or activation state to ignore it.

Rule precedence remains per capability. Scope metadata is read only from that
capability's winning policy ID and revision. It is never unioned with a losing
policy's ports or principals, and a losing broad allow cannot rescue an insufficient
winning scope. The winning deny continues to deny that capability as before.

Every requested adapter lease must fit both the configured TTL limit and its
winning policy's `valid_until`. Exceeding either is rejected, not silently shortened.
Integer timestamp conversion rounds policy starts up and policy deadlines down.
Zero, negative and overflowing lifetimes fail closed. Adapter leases remain
independent; expiry of an SSH or TCP lease does not change a separate mesh lease.
The graph models authorization dependencies, not a guarantee that a runtime
transport remains available for a credential's entire validity period.

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
route selections retain the existing externally-provided-route assumption and
never fall back. An exact choice that contradicts the request is rejected.

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
network policy. Explicit legacy TCP-only requests are unchanged.

## Planning audit

Completed authorizations and policy-planning denials write an `access.plan` audit record and a
`policy.plan.evaluated` v1 outbox event inside the same authorization transaction.
A storage or evidence-validation failure aborts that transaction. The existing
`policy.decision.evaluated` v1 event and signed adapter contracts are unchanged.
Its concrete evaluated intent describes the selected candidate; the new planning
event separately records the original exact/automatic selection mode.

The new [contract artifact](../contracts/artifacts/policy-plan-evaluated-v1.schema.json)
contains the decision/attempt ID and versioned planning evidence:

- Authenticated domain, subject, device, target, evaluation time and outcomes.
- Concrete resource bindings and the deployment declarations evaluated at that time.
- Each candidate's mechanism count or stable rejection reason and capability.
- The selected candidate and deterministic selection rule.
- The selected scoped abilities, their containing effective permissions and the
  winning policy IDs/revisions.
- Goal indices and executable steps with prerequisite/provided ability indices.

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

Add further implemented adapters and deployment candidates with complete scoped
effects. Stored policies still use the compatibility capability vocabulary and
one SSH principal per row; policies do not yet expose a general ability-expression
language or scope-specific deny precedence. The mTLS service audience remains
trusted deployment configuration. Wildcard resources, CIDR containment, dynamic
route discovery and mixed per-service routing are not modeled. Runtime enforcement
and revocation continue to enforce the signed scopes.

## Validation

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
agreement. It can also be invoked separately after the suite. The reconnect fixture
resets only the PoC client's cached WireGuard transport after a revoked peer is
re-authorized; it does not alter the target agent's granted membership or TCP rules.

The strict stored-policy decoder also has a read-only LXC PostgreSQL regression
that constructs typed rows without modifying stored policies. It verifies that a
valid allow and an invalid deny cannot yield a partial snapshot, in either order:

```sh
AUTHORITY_DB_HOST=$(mise run db:status | awk '/^ip: / { print $2 }') \
  cargo test -p authority-control-plane stored_policy_capabilities_fail_closed_in_postgres -- --ignored
```

It uses the local development credential file (or `AUTHORITY_DB_PASSWORD` /
`AUTHORITY_DB_PASSWORD_FILE`) and is explicitly opt-in outside LXC environments.
