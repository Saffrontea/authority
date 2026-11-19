# Contract governance

Files in `contracts/artifacts` are the source of truth for process-boundary
messages. Rust types are implementations of those contracts, not the source.

Every contract change must:

1. update or add a versioned artifact without rewriting an existing meaning;
2. add valid and invalid test vectors;
3. update `manifest.json` deliberately when artifact bytes change;
4. pass Rust conformance tests for every consumer and provider;
5. document security impact when signed fields, audience, nonce, or lifetime
   semantics change;
6. use a new major contract version for field removal or semantic changes.

The v1 signing representation is defined by
`IssuanceAuthorizationV1::signing_preimage`. JSON bytes are never signed.
`NetworkAccessGrantV1` uses an independent domain separator so an SSH
authorization signature cannot be replayed as a WireGuard peer grant. Its
signed peer key, mesh address, target node, policy, audience, and validity
window are all checked before application.

`AccessAuthorizationBundleV1` is the provider-facing result of one policy
evaluation. It contains the independently signed SSH and WireGuard projections
and requires both to share the decision nonce, issuer, domain, subject, device,
target, policy revision, and evaluation time. Consumers still accept only their
scoped signed projection, so neither consumer gains authority over the other.

`SignedDecisionRevocationNoticeV1` has its own domain separator and binds the
decision, target node, reason, monotonic sequence, audience, and retention
window. Push delivery and Pull reconciliation carry the identical envelope;
consumers must therefore apply it idempotently.

`MtlsIssuanceAuthorizationV1` is a third projection of the same policy
decision. It binds the client SPKI digest, SPIFFE identity, service audience,
target and decision ID. `SignedDecisionRevocationNoticeV2` replaces the
protocol-specific audience with an explicit adapter set, allowing one signed
notice to be verified independently by WireGuard and mTLS consumers.

`PolicyPlanEvaluatedV1` records deployment selection and scoped planning evidence
in the `policy.plan.evaluated` outbox event. Its provider and replay validator are
implemented in `authority-policy-core::selection`, with consumer/provider vectors
in that crate's conformance tests and the Control Plane audit tests. It records
candidate authorization results, resource/deployment declarations, scoped abilities,
effective permission bounds, policy revisions, goals and executable dependencies.
It is an audit message with no signing preimage and grants no authority. Decoding
it cannot construct an authorized plan for projection. Existing signed contract
fields, audiences, nonces and lifetime semantics are unchanged. Automatic route
selection is an explicitly proof-bound HTTP request option; it cannot turn a
server-unavailable or policy-denied route into an authorized implementation.

`PolicyPlanEvaluatedV2` separates direct credential/admission authority from derived
usable authority. It adds an operator-declared environment snapshot and grounded
derivation steps (`after_mechanisms`, prerequisite and output indices). Replay
requires the complete mandatory closure and rejects missing facts, omitted effects,
unexecuted causes, or scope/lifetime substitution. Its outbox contract version is
2. V1 artifacts and records retain their original graph and serialization. Both
versions remain unsigned audit evidence and cannot be submitted as authorization.
