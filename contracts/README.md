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
