# Verification obligations and evidence

This work tracks the full verification target; a passing model is not a proof of
all production code. No Verus/Kani proof of the Rust implementation has been
established yet. Each row below identifies both current evidence and the remaining
obligation. Protocol schemas and signed bytes remain unchanged.

| Target | Required property | Current evidence | Remaining obligation |
| --- | --- | --- | --- |
| Ability graph / solver (Verus) | Soundness, completeness, minimum mechanism count | Independent execution-order oracle in `crates/planning-core/tests/reference.rs`, checked against the real `solve` | Machine-checked Verus proof, including closure termination, selected-set deduplication and BFS frontier ordering; implementation refinement |
| Scope containment (Verus / Kani) | No authority expansion, interval containment | Scope PBT, including all `i64` interval endpoints, constructive transitivity and identity rebinding | Machine-checked containment and arithmetic proofs for every scope variant |
| Contract projection (Verus / Kani) | Contract authority agrees with the authorized scope | Production `evaluate_scoped` → `project_authorized` PBT, independent contract field assertions and rebinding rejection | Proof of all adapter projections, overflow/failure paths and encoding correspondence |
| Revocation / distribution (TLA+) | Concurrency, reorder, retry, revocation safety | TLC safety and conditional liveness over 2 decisions × 2 adapters, plus safety and liveness mutations | Expiry, receiver restart and kernel failure/recovery model; trace correspondence with actual HTTP/DB/adapters |
| HTTP / DB / adapters (E2E / PBT) | Formal model and real system correspondence | Existing LXC E2E and DB concurrency/rollback regressions; new durable ledger state-machine PBT | Generated end-to-end action traces compared with the formal transition model |

## Reproducible checks

Run `mise run verification:check` for the current combined gate (Java 11+
required), or `mise run verification:pbt` for the Rust property suites. `PROPTEST_CASES`
can raise the case count, for example `PROPTEST_CASES=4096 mise run verification:pbt`.
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
for accepting a grant after a tombstone and acknowledging without adapter cleanup. A third mutation removes delivery/cleanup
fairness and must violate eventual revocation.
The Python runner keeps TLC state in temporary directories.

Existing system checks remain `mise run poc:e2e` for the default WireGuard route,
and `AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS=10.77.0.1 mise run poc:e2e` for an
available existing route. The PostgreSQL regression remains:

```sh
AUTHORITY_DB_HOST=<lxc-db-address> cargo test -p authority-control-plane \
  access_policy::tests:: -- --ignored --test-threads=1
```

These existing E2E scenarios do not yet constitute model-based generated traces.

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
