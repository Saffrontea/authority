# Verification obligations and evidence

This work tracks the full verification target; a passing model is not a proof of
all production code. Verus now proves the abstract solver and directly checks the
production TTL containment and checked-lifetime predicates. Source-derived value
models also cover all scope variants, binding checks and projection material. The
source-derived BFS queue/visited/budget transitions now prove soundness,
completeness with a sufficient budget, minimum mechanism count and termination.
Private checked construction establishes the projection invariant; concrete closure
refines the least fixed point. Standard-library/encoding representation internals
and the lexicographic tie-break are not universally proved.
Each row identifies both current evidence and the remaining obligation. Protocol schemas and signed bytes remain unchanged.

| Target | Required property | Current evidence | Remaining obligation |
| --- | --- | --- | --- |
| Ability graph / solver (Verus) | Soundness, completeness, minimum mechanism count | Source-derived closure and BFS transition proofs: soundness, bounded completeness, minimum mechanism count and termination; independent/native PBT | Stable lexicographic tie-break proof; trusted collection/ID-view correspondence |
| Scope containment (Verus / Kani) | No authority expansion, interval containment | Verus source-derived proofs for all five variants, binding preservation, temporal authority non-expansion and transitivity; actual TTL predicate proof; atomic-authority PBT | Standard-library/encoding representation refinement beyond the documented value abstraction |
| Contract projection (Verus / Kani) | Contract authority agrees with the authorized scope | Checked factory discharges pipeline invariant; source-derived constructor/selection/collection/final-origin proofs; native PBT | Wire/consumer and representation correspondence |
| Revocation / distribution (TLA+) | Concurrency, reorder, retry, revocation safety | TLC safety and conditional liveness over 2 decisions × 2 adapters; peer lifecycle safety and conditional finite-workload expiry liveness, with GC/replacement/restart; counterexample mutations; live/timed system traces replayed by TLC | Arbitrary lifecycle trace generation and refinement beyond the tested scenarios |
| HTTP / DB / adapters (E2E / PBT) | Formal model and real system correspondence | LXC E2E and DB concurrency/rollback regressions; generated live/time/failure HTTP/DB/TCP/WG traces, live/timed TLC replay, SIGKILL recovery and command-failure tests; native authority/time/durable-state PBT | Broader arbitrary trace coverage, power-loss and other OS failure classes |

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
The Python runner keeps TLC state in temporary directories. The model also
includes receiver restart clearing installed bindings while retaining durable
records. `verification:traces` runs the live trace replay fixture and semantic/schema
mutations; it is part of `verification:check`.

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
and its composition with projection (including the 33 pipeline obligations),
26 for concrete closure (including the 20 abstract solver obligations), and 51 for
the source-derived BFS (which rechecks those 26). Counts include generated
obligations and are not independent end-to-end guarantees.

`mise run verification:verus:mutations` also requires proof failures for thirty-three
unsafe changes: widening deadlines, allowing unauthorized effects, selecting a
nonminimal solution, expanding TCP ports or SSH principals, dropping binding
checks, reversing lifetime subtraction, unchecked expiry addition, rebinding a
projection domain, substituting a TCP source, and substituting an SSH key. Pipeline
mutations additionally corrupt final TCP ports/endpoints, the WireGuard audience,
terminal nonce and mTLS identity; omit the SSH install contract; emit an unselected
WireGuard grant; or replace the approved TCP lifetime while collecting inputs.
Factory mutations drop binding/start checks or permit negative issuance times;
closure mutations ignore prerequisites, omit mandatory effects or stop before a
fixed point. BFS mutations drop final constraints, forbidden-mechanism checks or
permission checks; use the parent as a visit key; violate FIFO; exceed mechanism or
state bounds; or fail despite sufficient budget. These mutations must produce
verifier errors, rather than merely parse failures. The combined gate includes these checks. Own proof files may not introduce `assume`,
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

These are universal Verus theorems about that model, not bounded PBT results. The
source-derived concrete closure and BFS units below now connect production value
operations to it. They are not proofs of Rust collection memory internals, the
source adapter/compiler transformation or generic trait implementations. Stable
lexicographic tie-breaking remains checked natively, rather than universally proved.

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
rounds. The BFS proof above uses this closure result for its source node-extension
and initial-authority semantics.

## Source-derived BFS transitions

`formal/verus/bfs.rs` retains complete mechanism sequences and ability sets in
queue nodes. Its source adapter copies the production candidate guards, node
extension, permission pruning, visited admission, state-budget check and FIFO
insertion. The initial budget/permission checks and loop goal/mechanism guards are
also copied. Catalog construction and duplicate-ID rejection, empty queue/visited
initialization, selected-key collection and exhaustion return shape are checked
against the supported source form. Extra unmodeled statements fail extraction;
unknown fields in `Mechanism`, `Model`, `Request` or `Plan` require specification
updates. Native closure calls use the already-proved least-fixed-point result.

A valid BTreeMap catalog is viewed in its iteration order with unique IDs
injectively relabeled to positions. Ability values are similarly faithful labels.
The raw ID collector and ID/string/collection representations are trusted value
adapters, not a new machine proof of BTreeMap or arbitrary Eq/Ord/Clone code.
`canonical_labels.rs` checks this correspondence natively using arbitrary signed
mechanism IDs, structured ability labels, reversed catalog/rule insertion order,
forbidden/required selections, partial and exhaustive budgets, and exact result,
ability and execution-order equality. The independent exhaustive execution oracle
remains a separate check, so this metamorphic test is not presented as an oracle
for algorithm correctness.

The transition proof uses ghost-only expanded states alongside the real queue and
visited values. Its invariant establishes:

* Every queued node is an executable, authorized execution with no forbidden or
  repeated mechanism, exact mandatory-closure abilities and bounded length.
* Visited consists of expanded states and queued selected sets. Every child of a
  fully expanded state within the mechanism bound has been visited.
* Expanded states failed the goal/final constraint. Queue lengths are nondecreasing
  and span at most two adjacent mechanism-count layers.
* Each admission adds one visited set and one queued node. Popping removes one
  node. Thus `2 * (budget - visited.len()) + queue.len()` strictly decreases across
  outer iterations; finite catalog scans are proved by induction.

These facts connect to the independent reachable/execution specification. A goal
at the queue head has minimum mechanism count; if the queue empties there is no
valid solution within the mechanism bound. Invalid initial authority also admits
no valid execution, rather than being silently clipped. `SearchLimit` is never
interpreted as `NoSolution` or authorization.

A recursively constructed finite state space contains exactly the subsets of the
`N` mechanism IDs, with cardinality `2^N` (defined by repeated mathematical
doubling, without machine shift overflow). Each attempted new state is a member
not already visited. Therefore exhaustion implies `budget < 2^N`; with budget at
least `2^N`, the algorithm returns a solution exactly when the independent shortest
specification has one. Under smaller budgets, any returned solution is still
sound and globally minimum in mechanism count. The sufficient bound is not a
claim that all instances require that much memory.

The source loop is an ordered recursive fold in proof mode, with faithful queue
pop/push and set operations, as in the projection proofs. The final predicate must
be total, pure and depend only on the selected set/final abilities; this is the
existing solver contract. These are universal statements over arbitrary finite
catalogs under that value abstraction, not a proof of callback termination or
allocation success. They do not assert canonical lexicographic tie-breaking; native
oracle and canonical-label PBT continue to fix the existing deterministic behavior.

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
adapters. Receiver restart clears installed bindings and retains durable records.
The source publishes durable notices; delivery can occur in any order.
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
| `ReceiverRestart` | startup clears peers and the owned nft state before serving, while durable consume/tombstone ledgers survive |

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
partition or permanent adapter failure. No time bound or arbitrary-size universal theorem is claimed by this finite model.

`formal/tla/PeerLifecycle.tla` separately checks a single shared peer with two
immutable decisions, both staggered and equal deadlines. Its clock advances
monotonically; expired durable replay/tombstone records may be garbage collected.
It covers replacement, stale expiry tasks, burned nonces, revocation completion,
receiver crashes and clearing kernel state before the restarted HTTP receiver is
ready. Failures stutter; registry state is retained until kernel cleanup succeeds.
The checked invariants require registry/kernel agreement while ready, no cleanup
of a different decision, no resurrection after completed revocation, and durable
tombstones for completed decisions while still live. Mutations must expose expired
grant resurrection after GC, stale timer deletion, loss of the registry after a
failed expiry command, and restart without cleanup.

The actual expiry helper holds the policy mutex through its identity check,
kernel callback and registry deletion. A failed callback retains the registry and
the timer retries every second. The deadline uses a monotonic instant captured
before lock contention and kernel installation; grant validity is checked again
under the lock for both WG and TCP. A deterministic test checks that the mutex
is unavailable inside the kernel callback and failed cleanup can be retried.
Native PBT generates installation/replacement, stale/current timers, failures,
retries and clean restarts against an independent optional-binding oracle. It
calls the production expiry helper with a simulated kernel; restart/install steps
model the real ordering but do not execute `/usr/bin/wg` or HTTP. This suite is
included in `verification:pbt`.

The lifecycle model's `Spec` checks safety without fairness. Its separate
`SpecFair` checks `EventuallyExpiredPeerRemoved`: after the finite catalog's two
decisions expire, the model eventually reaches the terminal clock with no kernel
peer. It assumes weak fairness for clock ticks, receiver restart and successful
expiry cleanup. Removing expiry fairness must produce a temporal counterexample.
This is conditional finite-workload progress, without a time bound or a claim
about an unbounded stream of fresh decisions. It does not promise immediate WG
traffic denial at the deadline during scheduler stalls, crashes or kernel failure. TCP expiry is independently enforced by nft timeouts.
Both models assume verified immutable decision/expiry bindings and trusted clock
semantics; the lifecycle model does not include TCP's overlapping rules. The
generated E2E traces below exercise real HTTP, DB, adapter restart and kernel
admission, expiry, SIGKILL recovery and external WG command failure. These mappings
and tests are not a machine-checked refinement proof.

## Generated HTTP / DB / kernel correspondence traces

`mise run poc:e2e` runs `scripts/lifecycle-trace-e2e.py` after its fixed browser,
SSH, scope and expiry regressions. By default seeds `0,7,42` vary service scopes,
publication order, duplicate count, replay order, TTLs and process restart mode
in constrained live-binding and time/failure scenarios. Each trace issues fresh signed contracts through device-authenticated
browser requests, then drives the actual HTTP receiver and compares port admission
with an independent set oracle using the transitions of `Revocation.tla`.

The oracle tracks `published`, `consumed`, `active`, `tombstones` and `completed`
per decision/adapter. It distinguishes TCP authority from the independent WG peer
and overlapping TCP grants. Both managed TCP ports are probed after observable
operations. The trace rejects a run that exceeds its live-grant window, so expiry
cannot masquerade as successful revocation. It checks:

- committed notices pulled from the real DB retain their signed envelopes and
  monotonically paginated sequence numbers;
- a newer notice delivered before an older notice cannot suppress the older
  decision's revocation, and duplicate delivery is idempotent;
- revocation before consumption blocks a late grant; consumed grants reject
  replay; modified service scopes reject the original signature;
- revoking one TCP scope preserves another scope and WG transport;
- restarting the real systemd receiver clears installed authority while keeping
  durable replay/tombstone ledgers; restoring only WG still denies TCP, and a
  fresh TCP decision restores only its selected service;
- automatic delivery retries after HTTP 503 and removes an installed scope;
  repeated publication returns its original notice/sequence;
- WG removal is observed independently with mesh connectivity probes and direct
  successful kernel peer queries;
- removing execute permission from the real container's `/usr/bin/wg` causes
  revocation to return HTTP 500 while existing peer/TCP traffic still works;
  durable tombstones deny the late grant, and a later successful retry reports
  `peer_removed`, demonstrating the registry was retained;
- a journal cursor captured at fault injection requires a new expiry-command
  failure message before restoring permissions; the timer's own retry then
  removes the peer without another revocation request;
- generated short TCP TTLs expire independently, while a newer WG decision on
  the same peer survives the older timer and expires on its own deadline;
- SIGKILL must change the receiver PID and advance systemd's `NRestarts`; after
  automatic recovery, both actual ledger files must contain no records expired at
  process start, expired WG/TCP signatures remain invalid, a still-live consumed
  TCP grant still rejects replay, and a fresh valid signed decision installs only its selected port.

Live traces additionally run through `scripts/tla_replay.py` with the pinned TLC
checker before the E2E proceeds. The artifact records versioned reconstructed
states, declared transition edges and observation checkpoints. A successful grant
is expanded into `Consume` then `Install`; a successful cleanup into `Persist`
then `Complete`. Duplicate completions stutter. Receiver restart clears installed
bindings. Rejected/read-only requests retain the current state checkpoint.

TLC imports the actual `formal/tla/Revocation.tla`, constrains each next state to
the recorded state and requires the declared model action as well as `Next` (or
an explicit stutter). A bad edge deadlocks instead of being skipped. The successful
run must visit exactly as many distinct counter-indexed states as the artifact
contains. Replay-index fairness forces traversal of this finite recorded trace;
it is not an added runtime fairness claim. Model safety invariants and eventual
completion of published notices are checked too.

For each observation, TLC independently derives allowed ports from active WG/TCP
bindings and the requested service scopes, then compares them with actual socket
probe results. It does not take the Python oracle's expected port result as an
input. Semantic mutations must reject a changed actual port observation, omitted
nonce consumption and receiver restart retaining state. Schema checks reject
incomplete traces, unknown actions, unknown state fields, missing port probes and
unsupported schema versions.

The E2E runner now requires Java/TLC and checks tool availability before changing
LXC state. The same `TLA_JAVA` / `TLA_JAR` settings select the pinned checker for
both model checking and E2E replay. To replay an artifact later, set `TRACE_FILE` to the path printed by E2E, then run:

```sh
python3 scripts/check-tla-traces.py --scenario live "$TRACE_FILE"
```

The optional `--scenario live` selects the live projection; use
`--scenario time-and-command-failures` for timed traces. With no selector, every
trace in the artifact is checked. Unknown scenarios/versions fail rather than
being skipped, and an empty selection fails too. Old timed artifacts without
version 2 state/edge data cannot be upgraded by inference and fail the checker.
The serialized states are reconstructed logical state from the harness, not raw
receiver memory or DB snapshots. Thus this checks finite trace consistency and
actual admission observations against the model, not a universal refinement of
the implementation or proof of hidden internal state.

An E2E-only loopback proxy (`scripts/revocation-delivery-proxy.py`) forwards the
control plane's normal receiver traffic and temporarily returns HTTP 503 for
revocations. It records rejected sequence numbers so the retry test confirms its
particular notice encountered a real 503 before resuming delivery. Its block ACK
waits for earlier forwards to finish. Direct requests
use the original LXC receiver, so delivery order is controlled without changing
production services or adding a production fault-injection switch. The runner
starts/stops the proxy and removes its temporary endpoint file. The DB gate also
checks each tested decision's stored notice has exactly one matching audit and
outbox record, including repeated publication.

`AUTHORITY_E2E_TRACE_SEEDS=7 mise run poc:e2e` reproduces one seed; use a comma
separated list for more cases. `AUTHORITY_E2E_TRACE_FILE` selects the JSON artifact,
otherwise the path is `/tmp/authority-lifecycle-traces-<pid>.json`. The artifact
contains symbolic decisions, scopes, operations and expected/actual port results,
without signed envelopes or credentials. It is written even on failure. Each
seed includes a live-binding trace and a separate time/command-failure trace.

The time/failure oracle composes the live model with `PeerLifecycle` semantics:
WG installation replaces the shared peer's binding, a stale timer cannot remove
its replacement, failed commands retain pending WG state, and successful cleanup
removes the matching binding. TCP timeout independently removes expired port
rules. Short-TTL WG assertions use direct kernel queries through
`mesh:test:peer-present`, keeping their timing separate from long connectivity
probes. A query error fails the test. The test waits for actual cleanup before
observing WG expiry; it does not assert instantaneous traffic denial during
command failure. No source clock or expiry verifier is replaced. WG retains its
independent server TTL; the test separates issuance times to obtain distinct
signed WG deadlines and creates fresh TCP authority when needed to probe a peer
that outlives the earlier TCP lease.

The E2E-only `deploy/lxc/authority-lifecycle-test.sh` controls faults through the
existing privileged task agent. `mesh:test:wg-fail` records the original file mode
and a journal cursor before removing execute bits; `mesh:test:wg-restore` restores
that mode. Python finally blocks and the outer E2E shell trap both restore it.
`mesh:test:crash` sends SIGKILL and requires an observed automatic systemd restart,
without editing its service configuration. These tasks are absent from production
service flows. Manual recovery after an interrupted harness is
`mise run mesh:test:wg-restore`.

These are generated integration tests over constrained scenarios, not exhaustive
traces, an arbitrary-interleaving theorem or a proved refinement. SIGKILL tests
process failure, not power loss or interruption of a specific fsync. The command
fault is an actual executable-permission/spawn failure; it does not simulate all
kernel syscall errors, partial kernel updates, disk failure or arbitrary scheduler
stalls. Liveness remains conditional on eventual successful delivery and kernel
operations.


## Timed WG/TCP replay

`formal/tla/TimedAdmission.tla` composes the actual peer lifecycle model with
independent TCP kernel timeouts. The parent now takes an immutable `Expiries`
function and `MaxTime`; its original finite configurations still use deadlines
2/3 and a terminal clock of 3. This parameterization lets replay use the actual
signed expiry seconds, translated to a local trace epoch, without changing the
receiver clock or issuing shorter synthetic WG grants.

The combined exhaustive safety configuration has two WG and two TCP decisions.
It checks type constraints, peer/registry agreement while ready, no cross-decision
cleanup or resurrection, live revocation durability, and no expired TCP rule in
the active kernel set. Mutations must expose lost TCP timeout pruning and
reinstallation of a revoked TCP decision. This finite configuration does not
prove arbitrary catalog sizes or universal implementation refinement.

`scripts/timed_trace.py` records a version 2 logical state history in each timed
E2E trace. Integer clock ticks expire TCP rules independently of receiver readiness;
WG expiry retains its pending peer until successful cleanup. TCP tombstone
retention uses the notice deadline (the later bundle expiry), separately from
TCP admission expiry; GC cannot drop a live notice just because its TCP rule
has timed out. WG replacement keeps
old timer identities, failed commands stutter, crash loses volatile registry/timers,
startup collection drops expired durable records, and recovery clears installed
peer/TCP state. The history keeps declared actions and immutable per-binding
expiries. TCP port authority is taken from requested scopes and must match the
issued grant, while expiry is taken from signed contracts.

`scripts/timed_tla_replay.py` imports both actual TLA+ modules and replays every
recorded edge against `NextTimed` and its declared action. Declared expired,
revoked and replayed grant rejections additionally require their corresponding
state guards. Unknown actions or state fields fail before TLC. As with live replay,
the visited counter-indexed state count must equal the record count; invalid
transitions deadlock, and replay-index fairness forces finite traversal.

TLC computes port admission from the current physical peer binding and unexpired
TCP rules and compares it with both actual socket probes. Successful direct kernel
peer queries are checked separately against peer presence. During deliberate WG
executable failure, that query is unavailable and explicitly marked unmeasured;
port observations still occur, including a fresh TCP lease proving the expired
peer remains installed until its timer retry succeeds. Startup GC, expired-signature
rejection, retention of a live consumed TCP nonce, and fresh post-GC authorization
are part of the replayed history.

The independent fixture exercises replacement, ticks, failed expiry, expiry cleanup,
crash, GC, recovery and revocation. It also keeps a TCP revocation tombstone
after TCP expiry while the longer WG/notice interval remains live. Seven semantic mutations must expose changed
port/peer observations, stale-timer deletion of a replacement, retaining an expired
nonce at collection, accepting an expired grant, corrupting clock/TCP state, and
accepting a consumed TCP grant. Schema counterexamples reject incomplete traces,
invalid expiry values, unknown actions/fields and missing port probes. These checks
are included in `verification:traces` and therefore `verification:check`.

This validates finite logical reconstructions and actual admission/peer observations.
Hidden memory state is inferred from successful operations and receiver ordering;
it is not sampled or universally proved. Clock ticks are monotonic logical seconds;
clock rollback, power loss, partial kernel updates and arbitrary OS failures remain
outside these traces. The safety model preserves the existing boundary: WG cleanup
progress is conditional on successful external operations, while TCP timeout is
independently enforced in the kernel.


TLC standard-library extraction uses a per-invocation Java temporary directory,
which is removed with checker state. The browser E2E similarly owns an explicit
Chrome user-data directory and removes it after closing its session/driver. Each
run uses a fresh E2E username so virtual Passkeys do not accumulate on one account
and hit browser authentication-list limits. This
keeps repeated gate/E2E runs from accumulating browser profiles or sharing checker
scratch files. Logical trace JSON artifacts remain available for replay.
