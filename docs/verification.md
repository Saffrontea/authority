# Verification obligations and evidence

This work tracks the full verification target; a passing model is not a proof of
all production code. Verus now proves the abstract solver and directly checks the
production TTL containment and checked-lifetime predicates. Source-derived value
models also cover all scope variants, binding checks and projection material. The
BFS queue/visited/budget implementation and standard-library/encoding representation
internals are not yet universally proved. The checked private constructor now
establishes the input invariant needed by the source-derived projection pipeline;
the concrete closure iteration also refines the least fixed point and terminates.
Each row identifies both current evidence and the remaining obligation. Protocol schemas and signed bytes remain unchanged.

| Target | Required property | Current evidence | Remaining obligation |
| --- | --- | --- | --- |
| Ability graph / solver (Verus) | Soundness, completeness, minimum mechanism count | Verus concrete closure termination/least-fixed-point refinement, selected-set equivalence, execution/layer correspondence and shortest-search theorems; native PBT | BFS queue/visited/budget refinement and deterministic tie-breaking proof |
| Scope containment (Verus / Kani) | No authority expansion, interval containment | Verus source-derived proofs for all five variants, binding preservation, temporal authority non-expansion and transitivity; actual TTL predicate proof; atomic-authority PBT | Standard-library/encoding representation refinement beyond the documented value abstraction |
| Contract projection (Verus / Kani) | Contract authority agrees with the authorized scope | Checked factory discharges pipeline invariant; source-derived constructor/selection/collection/final-origin proofs; native PBT | Wire/consumer and representation correspondence |
| Revocation / distribution (TLA+) | Concurrency, reorder, retry, revocation safety | TLC safety and conditional liveness over 2 decisions × 2 adapters, plus safety and liveness mutations | Expiry, receiver restart and kernel failure/recovery model; trace correspondence with actual HTTP/DB/adapters |
| HTTP / DB / adapters (E2E / PBT) | Formal model and real system correspondence | LXC E2E and DB concurrency/rollback regressions; durable ledger, all-scope authority and contract-time PBT | Generated end-to-end action traces compared with the formal transition model |

## Reproducible checks

First run `mise run verification:verus:setup` to install the pinned verifier and
its private Rust toolchain. Then run `mise run verification:check` for the combined
gate (Java 11+ also required), or `mise run verification:pbt` for the Rust property
suites, including contract timestamp properties. `PROPTEST_CASES` can raise the case count, for example `PROPTEST_CASES=4096 mise run verification:pbt`.
Proptest minimizes failures and reports regression seeds. The oracle uses bitsets
and execution-order enumeration, rather than production's sets, BFS queue and
selected-set memoization. Its ability and mechanism universes are each at most six;
it also generates up to six mandatory derivations. These are randomized bounded
checks, not universal proofs.

Run `mise run verification:tla` with Java 11+ installed. `TLA_JAVA` can select the
Java executable; `TLA_JAR` can select a predownloaded jar. The checker is pinned to
[TLC v1.7.4](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4) and its SHA-256
is checked even when supplied locally. Otherwise the script downloads the jar to
`.cache/formal`. Missing tools fail the task rather than silently skipping it.
Run `mise run verification:tla:mutations` to additionally require counterexamples
for accepting a grant after a tombstone and acknowledging without adapter cleanup.
A third mutation removes delivery/cleanup fairness and must violate eventual revocation.
The Python runner keeps TLC state in temporary directories.

Existing system checks remain `mise run poc:e2e` for the default WireGuard route,
and `AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS=10.77.0.1 mise run poc:e2e` for an
available existing route. The PostgreSQL regression remains:

```sh
AUTHORITY_DB_HOST=<lxc-db-address> cargo test -p authority-control-plane \
  access_policy::tests:: -- --ignored --test-threads=1
```

These existing E2E scenarios do not yet constitute model-based generated traces.

## Verus proofs and source correspondence

`mise run verification:verus` checks the solver, direct-source TTL/checked-arithmetic
kernels, and source-derived scope/projection value models. Reported counts are 20
for the solver, four for direct TTL containment, seven for scopes, eight for
checked lifetimes, nine for material projection (which rechecks the seven scope
obligations), and 33 for the conditional complete projection pipeline (which
rechecks shared scope/material/lifetime obligations), 35 for checked construction
and its composition with projection (including the 33 pipeline obligations), and
26 for concrete closure (including the 20 abstract solver obligations). Counts
include generated obligations and are not independent end-to-end guarantees.

`mise run verification:verus:mutations` also requires proof failures for twenty-five
unsafe changes: widening deadlines, allowing unauthorized effects, selecting a
nonminimal solution, expanding TCP ports or SSH principals, dropping binding
checks, reversing lifetime subtraction, unchecked expiry addition, rebinding a
projection domain, substituting a TCP source, and substituting an SSH key. Pipeline
mutations additionally corrupt final TCP ports/endpoints, the WireGuard audience,
terminal nonce and mTLS identity; omit the SSH install contract; emit an unselected
WireGuard grant; or replace the approved TCP lifetime while collecting inputs.
Factory mutations drop binding/start checks or permit negative issuance times;
closure mutations ignore prerequisites, omit mandatory effects or stop before a
fixed point. These mutations must produce verifier errors, rather than merely parse failures. The
combined gate includes these checks. Own proof files may not introduce `assume`,
`admit`, or unchecked external bodies/specifications.

The verifier is pinned to
[Verus 0.2026.11.02.8bf68ee](https://github.com/verus-lang/verus/releases/tag/release/0.2026.11.02.8bf68ee)
(commit `8bf68ee741df833ea5d0fe6a2255126fdea87e47`) with Rust 1.99.1. The setup script
supports Linux aarch64 and x86_64, verifies the release archive SHA-256 and checks
installed files against that archive on every run. The Rust toolchain lives in
`.cache/formal/rustup`; setup uses `--no-self-update` and does not change the user's
Rust installation, Cargo cache or workspace compiler. A missing toolchain, changed
source shape, lost proof obligation, checksum mismatch or verifier failure fails
the task. It never silently skips a proof.

`formal/verus/validity.rs` is a proof template. The checker extracts the exact
`Validity` fields/types and the complete `Validity::contains` expression from
`crates/policy-core/src/scoped.rs`, then injects both into the proof. It checks the
expression for equality with the mathematical integer interval predicate and
proves that a contained interval cannot have a longer duration. This covers all
`i64` endpoints, including invalid/negative/overflow-edge intervals, without
replacing the implementation with a separately maintained predicate. Signature or
field-shape changes require updating the extractor explicitly. The template alone
is not the production-source proof; use the task rather than checking its empty
injection placeholders directly.

`formal/verus/scopes.rs` uses the production declarations and method bodies for
`AbilityScope::contains`, `ScopedAbility::contains`, `kind` and interval inclusion.
The source adapter in `scripts/verus_sources.py` lifts `String` to character
sequences, `BTreeSet` to finite mathematical sets, UUIDs to `u128`, and IPv4 values
to `u32`. Standard value operations (equality, nonempty, membership, subset, and
`iter().all`) are translated explicitly. New variants fail the adapter until the
model is extended; unknown operations/types fail verification. These are proofs
of the **source-derived value model**, not verification of the heap-backed Rust
collection implementation or a proved compiler transformation. `verification:sources` tests extraction
against nested comments, quoted/raw strings, character literals, malformed input
and duplicate/missing injection points; it is included in the combined gate.

Authority has an independent atom semantics: one peer, route, SSH principal,
service identity, or TCP port. If a requested ability is contained, every atom it
permits at a given binding/time is also permitted by the grant. The model proves
kind/request-shape preservation, transitivity and preservation of all four binding
fields and TTL containment. `containment_model.rs` checks the actual Rust predicate
against this atom-set oracle across all variants, key/token/endpoint changes,
principal/port subsets and additions, zero/empty/oversized sets, binding changes
and arbitrary `i64` intervals.

`formal/verus/expiry.rs` verifies the exact production bodies of `valid_ttl_seconds`,
`projection_expiry` and `lifetime_seconds`, including Rust `checked_add` and
`checked_sub`. It proves equality to mathematical bounded arithmetic, round-trip
reconstruction of the approved expiry and no widening. All projection constructors
use the checked expiry kernel; contract validators and scoped projection use the
checked lifetime kernel. This fixes overflow in legacy all-adapter projection and
in validators receiving extreme timestamps. Existing contract semantics permit
negative Unix timestamps; these proofs/tests preserve that behavior. Policy
interval containment separately requires nonnegative requested starts.

`formal/verus/projection.rs` extracts the common-binding guard from
`project_authorized` and the complete `project_scope` field mapping. It proves
that every materialized key, token, principal set, service audience, source,
destination and port set comes from the approved scope, without duplicates or
extra principals/ports. A route-only ability produces no contract material.
Common domain/user/device/target, policy, issuer and issuance time must match the
approved plan. Sequence conversion is modeled as finite set enumeration; the
proof preserves membership/cardinality and does not claim canonical sort order.
IPv4/UUID/domain string encoders are opaque functions, with no injectivity axioms:
field equality is to the exact approved value's encoding. Native field assertions
and E2E cover the real encoders, while a universal encoding/refinement proof remains.

`formal/verus/constructors.rs` lifts the complete bodies of `ssh_contract`,
`mtls_contract`, `project_network` and `project_tcp`. An independent common-binding
specification requires version, issuer, domain, user, device, target, policy and
all validity fields to agree, as well as each adapter's material, nonce and
audience. The mathematical models of String/Vec cloning preserve values. Rust
`Result`/`Option` propagation is translated to explicit early-return matches;
unknown unsupported propagation paths remain visible and fail verification.
Native protocol constants are read from production source. The mTLS nonce encoder
is opaque, like IP/UUID encoders, without injectivity or collision assumptions.

Contract validation is modeled as an arbitrary predicate for each complete
contract. Proof-mode validation returns success exactly when that predicate holds,
without assuming success. Therefore a successful return must preserve all fields
regardless of the validator's decision. This is a constructor-consistency proof,
not a proof of every validator or the cryptographic verifier. Actual timestamp
validators retain their independent PBT against integer arithmetic.

`formal/verus/selected.rs` checks the entire production mechanism-match body as a
state transition and proves its ordered fold by induction over every finite
mechanism sequence, including empty sequences, duplicates and arbitrary order.
Exactly selected adapter kinds have output contracts; SSH/mTLS issue/install
pairs preserve their distinct nonces/audiences. Unselected inputs need not exist
or have valid lifetimes. The source adapter checks the exact derived-Default
initialization, Vec iteration and final Result boundary. It uses a recursive proof
of the same fold, rather than a Verus proof-mode loop. Early failures return an
error, never a partial `SelectedProjections` value.

`formal/verus/authorized.rs` connects the common-binding guard, complete ability
collection body, actual selection record, input assembly and final call. Every
successfully returned contract has an origin witness in the approved ability set:
its material and full interval equal that ability's approved scope/interval; SSH
installation also retains its authorized terminal-token hash. No union of multiple
ability scopes is substituted for one authorization. Each output still satisfies
the complete common-binding/selection predicates. BTreeSet enumeration is a finite
sequence with the same members; the proof works for any such order. The production
accessors must remain their exact identity-field reads or extraction fails.

The isolated consumer theorem requires `plan_bindings_valid`: the plan's issuance
time is nonnegative, and every realized ability carries the plan's binding and
start time. `formal/verus/factory.rs` now discharges that precondition using the
actual `AuthorizedPlan::new` body. The private checked constructor rejects any
candidate violating those facts and otherwise preserves the complete realization,
policy reference and evidence. It does not require a correct solver to establish
this particular binding/time invariant. Its composition theorem constructs a plan
and projects it without a `plan_bindings_valid` precondition.

`evaluate_scoped` must use this constructor and return its checked result directly.
The source adapter checks the private field layout, field-derived Clone, allowed
methods, identity accessors, evidence-only selection mutation, direct construction
sites and the post-construction return boundary. This is a checked-constructor
invariant proof under the documented value/source-adapter abstraction, not a new
proof of policy precedence, evidence consistency, all solver properties or the
Rust compiler. Native constructor PBT generates mismatched domain/user/device/node
bindings, shifted starts and extreme issuance times, checking both acceptance and
preservation of all supplied plan/evidence data. The constructor adds one bounded
scan of the realized ability set; valid existing authorizations are unchanged.

Native factory PBT also checks the invariant through successful `evaluate_scoped`
and `project_authorized` for independent SSH/mTLS/network lifetimes.
`selected_agrees` is independently checked against native `project_plan` with
generated mechanism sequences, missing input masks, invalid/overflowing lifetimes,
output presence, metadata and adapter fields. This is correspondence evidence;
the source adapter/compiler transformation itself is still a trusted boundary.

Contract/request declaration fields are checked against explicit supported layouts;
adding authority fields requires extending the specifications. Source adapter tests
cover nested call arguments and Result propagation, schema drift, source-injection
boundaries and presence of complete constructor/collection/selection code. The
pipeline proof does not cover byte serialization, signature verification, encoder
injectivity or adapter consumption. Those remain separate correspondence work.

`formal/verus/solver.rs` is an unbounded mathematical model, using arbitrary
scoped-ability labels and a finite catalog with unique positional IDs. It proves:

* The intersection-defined Horn closure is extensive, closed, least and monotone.
* Incremental mandatory closure equals closure over accumulated effects.
* Any catalog-valid execution has the same abilities as its selected mechanism
  set, establishing the semantic basis for selected-set deduplication.
* Valid distinct-mechanism execution sequences correspond in both directions to
  reachable search layers. Reachable states have authorized abilities, no
  forbidden/invalid IDs, and mechanism count equal to layer depth.
* Layer search returns an executable, goal-satisfying, constraint-satisfying
  minimum-length witness, or establishes absence of any valid execution within
  its mechanism bound. The final predicate may require extending a goal-reaching
  state, provided it depends only on the selected set and final abilities.

These are universal Verus theorems about that model, not bounded PBT results. They
are **not yet a proof of production's concrete BFS**: translating arbitrary Rust
IDs to positional IDs, queue/frontier order, visited-set admission, search-budget
accounting and lexicographic tie-breaking
still require implementation refinement. The PBT reference currently checks the
concrete implementation against an independent execution model with those runtime
behaviors; it is evidence of correspondence, not a universal refinement proof.

## Concrete closure implementation

`formal/verus/closure.rs` copies the production `Derivation` shape, complete rule
application body and stopping condition from `planning-core::closure`. Finite
BTreeSets are lifted to mathematical finite sets. Each round scans rules in the
same sequential order; the outer loop is proved by well-founded recursion on the
number of possible effects not yet present. A ghost-only universe is constructed
from the seed and all declared effects, so callers need no universe-bound premise.
Every nonterminal round strictly grows the set within this finite universe.

The proof establishes extensiveness, containment in the least Horn closure,
application of every initially enabled rule in each round, and equality with the
least fixed point when the production cardinality stopping test succeeds. Equal
size implies equal sets because every round is monotone. Closure is independent
of derivation order and retains all mandatory composition effects. The input
ability label universe and finite rule/set cardinalities are unbounded by the
PBT bitset size. Standard value-preserving Clone and consistent Eq/Ord semantics
remain part of the same collection abstraction used elsewhere.

The source adapter consumes the exact loop/round/return shape and fails on
unsupported changes. The proof is a refinement of that source-derived iterative
value model, not a verification of BTreeSet memory internals. A direct native
closure PBT compares it with independent synchronous bitset rounds, including
empty premises, cycles, reordered rules, idempotence and growth through multiple
rounds. This closes the concrete closure obligation; queue processing, visited-set
deduplication and search budgets in the rest of `solve` remain separate work.

## Solver specification boundary

For catalog `C`, mandatory derivations `D`, existing abilities `A0`, permission set
`P`, and goals `G`, let `closure_D(A)` be the least fixed point of all enabled
monotone derivations. A valid execution is a sequence of distinct, non-forbidden
mechanism IDs. Each step must have all prerequisites in the previous closure.
Its closure must remain within `P`; its final closure contains `G` and its selected
set and abilities satisfy the pure final predicate. Execution length must not
exceed the requested mechanism bound.

* **Soundness:** `Ok(plan)` implies the full execution specification above, and
  the reported abilities equal its final closure, including mandatory effects.
* **Completeness:** with unique IDs and budget at least `2^|C|`, `NoSolution`
  implies no valid execution exists within the mechanism bound. `SearchLimit`
  carries no proof of absence. Duplicate IDs are an invalid catalog.
* **Minimality:** every returned plan has minimum mechanism count among valid
  executions. Stable lexicographic execution order breaks ties. Even a smaller
  search budget may return only that same minimum plan or fail closed.

The generated oracle includes initial abilities, hyperedge prerequisites, cyclic
and empty-premise derivations, unauthorized side effects, forbidden mechanisms,
mechanism bounds and final constraints that can require extending a goal-reaching
plan. Catalog/rule reversal checks order independence. Scope-labelled abilities
must encode the entire authority, not just OSI/layer names. External transport
availability, undeclared effects and mutable facts are outside this monotone model.

## Revocation model boundary and implementation correspondence

`formal/tla/Revocation.tla` models authenticated, unexpired bindings as
`<<decision, adapter>>` pairs. Its finite configuration has two decisions and two
adapters. The source publishes durable notices; delivery can occur in any order.
Duplicates, network failures and failed cleanup can stutter without changing state.
A dispatcher restart clears its acknowledged cache. Durable tombstones are never
cleared in this live-notice model. Sequence numbers are not a global watermark:
a later notice cannot suppress an older notice for another binding.

| Model transition/state | Implementation boundary |
| --- | --- |
| `Publish` / `published` | `persist_revocation` writes the signed notice, audit and outbox in a PostgreSQL transaction |
| `Consume` / `consumed` | network-agent consumes the durable replay nonce before attempting adapter installation |
| `Install` / `active` | grant verification and policy mutex protect installation against the revocation path |
| `Persist` / `tombstones` | `apply_revocation` persists `wg_<decision>` / `tcp_<decision>` before removing adapter state |
| `Complete` / `acknowledged` | successful adapter removal precedes the HTTP acknowledgement; duplicate notices still perform cleanup |
| `DispatcherRestart` | delivery cache is volatile; source notices and receiver tombstones remain durable |

These are reviewable abstraction mappings, not a proved refinement. In particular,
the model does not model the byte encoding, verifier, operating system or network
itself. `crates/replay-ledger/tests/model.rs` compares the actual durable primitive
with an independent history across duplicate/reordered consumes, both adapter
prefixes, monotonic time advancement and reopening the file. It does not prove
power-loss atomicity or coordination between multiple ledger instances.

TLC checks type invariants, acknowledgement only after durable tombstones,
authenticated revocation origins, installation only after nonce consumption, and
**no reactivation after completed revocation**, including after dispatcher restart.
An already installed adapter may remain active between tombstone persistence and
successful cleanup. Publishing a notice remotely is not immediate enforcement.

Eventual completion requires weak fairness for delivery/persistence and successful
cleanup for each published binding. This assumption means failures eventually
permit progress; the implementation cannot guarantee it during a permanent
partition or permanent adapter failure. No time bound, receiver restart safety,
expired-tombstone safety or arbitrary-size universal theorem is claimed by this
finite model. Those remain explicit work items before the full goal is complete.
