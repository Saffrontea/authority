# Signed endpoint observations

The live Control Plane no longer uses `device.nodes.endpoint_facts` to enable
mechanisms. The column remains in the migration history and the PoC bootstrap
writes an empty array. Authorization requires a fresh challenge/report exchange
with the registered target, followed by verification in the policy/decision
transaction. There is no fallback to a previously cached report when refresh
fails. Environment facts enable catalog edges; they never grant authority.

This implementation targets the managed LXC profile: one configured actuator
origin per CP, WireGuard interface, SSH principal `deploy`, and the two configured
mTLS service instances. Arbitrary SSH configurations and non-WireGuard existing
routes are not automatically discovered or trusted. The managed PoC has one
active concrete observation context per actuator. Switching its domain/resources
conservatively withdraws earlier installations. Concurrent clients with different
resource contexts require a multi-context support store before broader rollout.

## Exchange and commit boundary

1. A device-signed, authenticated authorization request names its registered
   device and target. Before probing, the CP checks ownership and an applicable
   allow-policy scope. The target must match the configured actuator identity.
2. Under the target node's UPDATE lock, the CP allocates a monotone revision and
   unpredictable 32-byte nonce. Its Ed25519 signature binds the domain, target,
   audience, challenge lifetime, concrete source/destination, principal, SSH CA
   fingerprints, mTLS CA digest and service audience. The transaction commits
   before network I/O.
3. The target checks the CP signature and challenge lifetime, consumes the nonce
   in its durable replay ledger and runs its trusted probe. Its registered
   identity key signs the complete report, including the challenge, process/OS
   boot instance, oldest sample time, lease expiry, configuration digest, probe
   implementation digest and typed facts. Unknown or duplicate facts are rejected.
4. A second READ COMMITTED transaction locks the node, checks the exact pending
   challenge and current registered key, then consumes the challenge and stores
   the report atomically. Failed or superseded publications cannot overwrite it.
5. The authorization transaction acquires the policy advisory guard, locks the
   node for SHARE **before** starting the joined snapshot read, then verifies the
   report again against current identity/resources. Every selected ability must
   fit its validity. Policy, audit, issuance ledger and outbox commit together.
   Evidence retains the complete signed report under `resources.observation`.

The preliminary node lock matters: a single SELECT that waits for a row lock can
otherwise retain the older statement snapshot of a joined observation. Every
observation writer uses the same node lock. Multiple CP instances share revision,
challenge-consumption and rate state in PostgreSQL; they do not use process-local
revocation or freshness caches.

The wire contracts are [challenge v1](../contracts/artifacts/endpoint-challenge-v1.schema.json)
and [observation v3](../contracts/artifacts/endpoint-observation-v3.schema.json).
Their canonical preimages use different domain separators. Signature verification
uses the registered key, not a public key supplied by the reporter. Structural
contract validation and pure planning-evidence replay do not themselves
authenticate a node or its policy membership. Symbolic/model tests can supply
assumed environment facts without runtime provenance; the live API cannot.

The versioned signing representation is fixed by the independent Python-generated
`basic.preimage.hex` vectors. It is the named ASCII domain separator plus one NUL
byte, followed by compact UTF-8 JSON without whitespace or slash escaping. Values
are bounded ASCII strings and nonnegative decimal integers. Object keys follow
the declared struct order, **not** RFC 8785/JCS sorting:

- challenge: version, audience, domain_id, target_node_id, nonce, revision,
  issued_at, expires_at, resources;
- resources: source, target, principal, ssh_ca_fingerprints, mtls_ca_sha256,
  service_audience;
- observation: challenge, boot_id, observed_at, expires_at,
  configuration_sha256, probe_sha256, facts, tcp_resources.

CA fingerprint arrays are lexically sorted. Fact arrays use the fixed enum order:
SSH trust, mTLS trust, TCP enforcement, mesh route, existing route. Duplicates
are rejected before signing/verification. Outer envelope signatures and key IDs
are not included in either preimage. A wire-format change must update the
explicit contract and signing vectors rather than silently changing serialization.

## What is probed

- **SSH trust:** systemd captures configuration/trust/principal hashes before
  sshd startup and confirms they are unchanged after startup. The receipt binds
  the running MainPID, process start tick and OS boot ID. The probe rechecks
  these and `sshd -T -C` for the concrete source/principal. The effective trust
  file must contain exactly the expected CA fingerprint set and the principal
  must be accepted by the captured root-only principal command. The receipt also
  pins the watchdog helper and requires static principal/key bypasses and PAM
  session migration to be disabled. An unrecorded change or reload
  requires a verified restart; merely changing a file never refreshes the receipt.
- **mTLS trust:** a root-only Unix socket reports the service's immutable loaded
  CA, domain, target, audience and process ID. The probe checks private directory/
  socket ownership and mode, and the systemd process identity before and after
  the request. TLS acceptors, including refreshed CRL contexts, use this same
  in-memory CA rather than re-reading a mutable trust file.
- **TCP enforcement:** the signed report includes the actual normalized managed
  port intervals. The kernel's actual nftables table, set type/flags,
  chain hooks/priorities and complete rule expressions must equal the structure
  installed by the actuator at startup. Only mutable set elements, rule handles
  and packet/byte counters are excluded from this structural comparison. This
  proves the configured enforcement mechanism exists, not a signed inventory of
  every installed grant. A separate root-owned read-only nft executable permits
  observation while actuator command-failure tests disable the mutation tool.
- **Routes:** the concrete target address must be present on an UP WireGuard
  interface, with the route for the concrete source using that interface. This
  is configured local routing, not proof of remote reachability. The LXC
  existing-route profile uses the same verified transport configuration.

## Live withdrawal and restart

The target probes its current support every five seconds. Missing support,
report expiry, or a changed resource/domain scope closes admission and clears
its WireGuard peers and TCP registry. Cleanup failures keep the state available
for retry. Withdrawal is deliberately conservative across the managed actuator;
it is not the subject/device selector revocation feature.

A monotone issuance-time fence is atomically persisted with mode 0600, file
fsync, rename and parent-directory fsync. Grants issued on or before it cannot be
installed after support returns. Startup advances the fence as well: even a
previously uninstalled old grant needs reauthorization after restart. Existing
replay/tombstone responses remain unchanged. A failed fence write leaves admission
closed and is retried; a new successful observation cannot reopen it without
successful persistence and cleanup. Repairing nftables does not revive old grants.

The report lease is 600 seconds and issued abilities cannot outlive it. A CP
challenge lasts 30 seconds; a probe has a 12-second deadline and CP HTTP has a
15-second deadline. Replies are bounded to 16 KiB, proxies and redirects are
disabled. One challenge is pending per node; at most 64 are issued per 30-second
window. Failures release that pending slot without extending old evidence. The
rate window and counter are shared by replicas. Clients need a new signed
request after a refused refresh.

CP, DB and target clocks must have at most two seconds of skew and must not jump
backwards. This is also an assumption of the existing absolute-time grants and
certificates. The target's fence includes the skew allowance; after a fence
advance it waits for a strictly newer issuance second before replying, at most
about five seconds with correctly synchronized clocks. Large clock errors fail
closed. This is not a substitute for generation-bearing grant contracts or
trusted-clock protection against arbitrary time rollback.

The detection interval is not an instantaneous guarantee: probing can take up to
its deadline, and kernel cleanup can fail and require retry. A DB transaction
cannot atomically freeze a remote kernel. Credential expiry and mTLS's DB/CRL/
OCSP/session leases remain independent enforcement boundaries; clearing network
state does not retroactively invalidate a bearer SSH certificate on unmanaged
transport paths. Protecting the configured transport remains a deployment trust
assumption.

## Deployment and repair

`mesh:agent-install` installs the root-owned probe, independent nft reader and
SSH startup receipt hooks. `mesh:mtls:install` configures private enforcement
sockets under `/run/authority-observation`, with 0700 directories and 0600 socket
modes. The service units allow writes to that runtime directory. The node signer
uses its existing identity file; the fence sits beside it as
`endpoint-observation-fence`.

The CP pins the public SSH bundle from `AUTHORITY_SSH_TRUSTED_CA_FILE` (default
`.secrets/ssh-trusted-user-cas.pub`, or the initial `.secrets/ssh-ca.pub` when no
bundle exists). The mTLS certificate comes from
`AUTHORITY_MTLS_CA_CERTIFICATE_FILE` (default `.secrets/mtls-ca-cert.pem`). The
mTLS services require `AUTHORITY_MTLS_OBSERVATION_SOCKET`, with a distinct path
per instance. Key rotation requires re-enrollment/updated trust configuration;
replacing a DB key invalidates earlier reports rather than silently trusting them.

After an unrecorded SSH trust change, deploy the intended trust bundle and
restart sshd through the managed unit. After nftables structural drift, repair
or restart the Network Agent to reinstall its rules. Then request fresh
authorization and reconnect the client tunnel if its previous WireGuard session
was discarded; old grants are intentionally unusable. Do not bypass a missing
report by populating `endpoint_facts`.

A node signature authenticates the reporting node, not the truth of a compromised
node. The probe and identity key are trusted target components. The probe digest
is signed provenance, not hardware-backed measurement/remote attestation. The
bootstrap token remains an external trust root; modeled administrative genesis,
bulk selector revocation and symbolic resource ranges are separate remaining work.

## Symbolic actuator coverage

Observation v3 signs the full `TcpResourcesV1` product, rather than ports alone.
Source ranges come from directly connected kernel routes on the managed
interface. Destination ranges are the canonical union of IPv4 addresses actually
assigned to that interface. Ports come from the four checked nft predicates.
These are bounds on ACL installation, not a claim that every source host is live
or that a credential creates a route. WireGuard peer source validation remains
independent. Policy must permit every requested address, port, and time segment.
The solver excludes unsupported products before plan selection; evidence replay
and the agent independently check the same subset relation. Shrinking any axis
withdraws earlier installations. V2 reports are not accepted as inferred coverage.

WireGuard membership still grants one registered source address. A CIDR TCP ACL
uses an existing route; it does not expand a peer's `AllowedIPs`. An explicit
direct request can select this path. Automatic selection also requires the
existing-route availability configured for that deployment; the default mesh
candidate cannot represent CIDR membership and must reject it.
