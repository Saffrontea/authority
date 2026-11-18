# Verification coverage audit — 2026-11-18

This audit maps the five requested verification areas to the implemented checks.
It records the kind and scope of the evidence, rather than treating a green test
suite as a universal proof of the entire deployed system. Detailed specifications,
trusted adapters and further verification work remain in [verification.md](verification.md).

| Requested area and property | Checked artifacts | Evidence and boundary |
| --- | --- | --- |
| Ability graph / solver: soundness, completeness, minimality with Verus | [solver.rs](../formal/verus/solver.rs), [closure.rs](../formal/verus/closure.rs), [bfs.rs](../formal/verus/bfs.rs), [lexicographic.rs](../formal/verus/lexicographic.rs); independent [execution oracle](../crates/planning-core/tests/reference.rs) and [ID-view properties](../crates/planning-core/tests/canonical_labels.rs) | Source-derived closure/BFS proofs establish authorized executable results, minimum mechanism count, canonical tie-breaking and termination. `full_budget_completeness` proves equivalence to the independent solution specification with budget at least `2^N`. Smaller budgets fail closed; any returned solution retains minimality. Finite catalogs are arbitrary in the proof, while faithful collection/ID views and a pure set/ability-dependent final predicate are assumptions. |
| Scope containment: no authority expansion and TTL containment with Verus | [scopes.rs](../formal/verus/scopes.rs), [validity.rs](../formal/verus/validity.rs), [expiry.rs](../formal/verus/expiry.rs); [atomic-authority oracle](../crates/policy-core/tests/containment_model.rs) | All five scope variants, domain/user/device/target bindings, interval inclusion, transitivity and checked timestamp arithmetic are covered. `scoped_authority_nonexpansion` relates containment to an independent atom-at-time interpretation. Rust/encoding representations are checked under the documented value abstraction, not proved as library implementations. |
| Contract projection: agreement with authorized scope with Verus and PBT | [checked construction](../formal/verus/factory.rs), [projection pipeline](../formal/verus/authorized.rs), [constructors](../formal/verus/constructors.rs), [signed-wire PBT](../crates/projection-core/tests/wire.rs), issuer/node `consumer_properties.rs` suites | Construction supplies the projection invariant; selected mechanisms, identity, exact scope/material and expiry retain authorized origins. Native tests continue through real JSON, Ed25519/OpenSSL and actual issuance/install functions. Certificate type, subject/device key ID, principals/SANs, public keys, certificate validity, replay and rejection side effects are checked. This combines value-level proof with finite generated implementation checks; it is not a proof of all cryptographic/codec internals. |
| Revocation / distribution: concurrency, reordering, retry and revocation safety with TLA+ | [Revocation](../formal/tla/Revocation.tla), [PeerLifecycle](../formal/tla/PeerLifecycle.tla), [TimedAdmission](../formal/tla/TimedAdmission.tla), [TLC runner and mutations](../scripts/check-tla.py) | TLC explores interleaved publish/consume/install/persist/complete/restart actions, durable tombstones, overlapping/replaced grants, failed expiry cleanup and independent WG/TCP timeouts. Safety checks include no resurrection, durable-before-ack and registry/kernel correspondence. Conditional delivery/expiry liveness requires the explicit fairness assumptions. Exploration is over the checked finite model configurations, not an unbounded production refinement proof. |
| HTTP / DB / real adapters: model/system correspondence with E2E and PBT | [generated LXC traces](../scripts/lifecycle-trace-e2e.py), [live TLC replay](../scripts/tla_replay.py), [timed TLC replay](../scripts/timed_tla_replay.py), [DB regressions](../bins/control-plane/src/access_policy.rs), native network/durable-state properties | Actual signed HTTP requests, PostgreSQL audit/outbox rows, TCP/WG kernel behavior, graceful restart, SIGKILL recovery and WG-command failures are observed. Actual state/action/port/peer traces are replayed through the model's `Next` relation. READ COMMITTED/row-lock waiting and atomic rollback, plus unknown-capability fail-closed behavior, are checked against real PostgreSQL. These are concrete finite correspondence checks; arbitrary traces, power loss and all OS failure classes remain outside the demonstrated evidence. |

## Reproducible validation

The combined gate is `PROPTEST_CASES=4096 mise run verification:check`, with the
pinned Verus installation and a configured Java/TLC environment as documented in
[verification.md](verification.md). It includes source-adapter regressions,
Verus proof/mutation checks, native PBT, TLC safety/liveness/counterexample checks,
live/timed trace replay fixtures and TCP probe fidelity tests. Missing tools,
unsupported extraction, lost obligations or missing expected counterexamples fail
the gate. Source proof units reject unchecked admissions and external bodies.

System validation uses the actual LXC fixtures:

```sh
AUTHORITY_E2E_TRACE_SEEDS=7 mise run poc:e2e
AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS=10.77.0.1 AUTHORITY_E2E_TRACE_SEEDS=42 mise run poc:e2e
AUTHORITY_DB_HOST=10.0.3.65 cargo test -p authority-control-plane access_policy::tests:: -- --ignored --test-threads=1
```

The selected seeds reproduce generated logical schedules; they do not make E2E
exhaustive. Full echo framing, one shared monotonic deadline and diagnostic
metadata strengthen the port observations without retrying an individual
observation or hiding a model mismatch. A failed bounded echo, including a
timeout, is recorded as lack of observed admission, not as proof of a particular
firewall rejection.

## Observed results

The checks above passed on 2026-11-18 with the TCP observation changes in this
revision:

- The combined gate passed with `PROPTEST_CASES=4096`. The concrete BFS unit
  discharged 66 obligations, and all 36 Verus mutations produced proof errors.
  The new observation suite passed seven tests, including 256 fragmentation cases.
- Default-route LXC seed 7 replayed 33 live states/20 port observations and 134
  timed states/13 observations through TLC. All 66 per-port diagnostic records
  were present in completed traces.
- Existing-route LXC seed 42 replayed 35 live states/21 port observations and 134
  timed states/13 observations. All 68 per-port diagnostic records were present
  in completed traces.
- Both LXC modes passed OpenSSH/TCP admission validation and the PostgreSQL
  planning audit (`audit=25, allow=23, deny=2, automatic=1`).
- Both real PostgreSQL regressions passed: transaction isolation/row-lock/rollback
  behavior and unknown-capability rejection.

The five requested areas therefore each have an implemented property check and
passing evidence at the scope stated in the table. The explicit trust boundaries
and finite exploration domains remain part of the guarantee; these results do
not establish universal library/OS correctness or exhaustive system refinement.
