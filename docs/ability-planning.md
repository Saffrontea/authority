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
abilities to seed into the solver. In this first version permission inclusion is
exact set inclusion. Wildcard scopes or interval containment require an explicit,
reviewed normalization into scoped abilities before solving.

The solver selects the fewest mechanisms and breaks ties deterministically by
mechanism ID and executable order. This is not an ordering of privilege: a broader
allowed plan may use fewer mechanisms. Final constraint predicates may depend on
the selected mechanism set and abilities, but not their execution order. Mechanism
exclusions and maximum plan size are also supported. Exhausting the explicit search
budget returns an error, never an allow decision. Search is exponential in the
worst case; the current access catalog has five mechanisms, hence at most 32 states.

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
This catalog preserves the current intent semantics; it does not yet model every
network or service deployment as a choice of interchangeable routes.

Policy evaluation first computes the effective permission envelope using existing
rule precedence and identity checks. It then solves within that envelope and keeps
the selected realization and the policy sources for its abilities in the decision.
`projection-core::project_plan` materializes only the selected mechanisms, requiring
only their input material. `NetworkRoute` is a planning step and emits no contract.
Both production authorization endpoints use this path. The old fixed `project`
function remains as a compatibility API.

The access catalog's ability enums are scoped by the enclosing authenticated
request. They are not yet the full resource/principal/port/time ability model.
The existing API still validates requested TCP ports, SSH principal bindings and
adapter lifetimes. Contract formats, DB policy capabilities and enforcement behavior
remain compatible. `ServiceIdentity` means presenting the specified identity, not
permission to execute every operation at a service.

## Next extension

Move the existing resource, principal, port and validity constraints into explicit
scoped ability values and permission containment, with adapter effects describing
their actual breadth. Add alternative deployment mechanisms to the catalog and
persist the selected mechanism/dependency trace with policy provenance. Only then
can the compatibility mapping from issuance permissions be removed. Runtime
enforcement and revocation must continue to enforce the authorized scopes.

## Validation

Planner tests cover alternative routes, unauthorized side effects, mandatory
composition closure, multi-input dependencies, cycles, scoped identity/resource
separation, final constraints, deterministic ordering and budget failures. A
property test compares the solver's answer and minimum mechanism count against
independent exhaustive subset enumeration. Existing policy properties continue to
check dependency closure, deny precedence and rule-order invariance. Projection
tests cover TCP-only selection, required dependencies and compatibility with the
existing infrastructure contracts.
