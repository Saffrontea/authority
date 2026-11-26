# Operator administration

The operator key and control-plane grant key are separate Ed25519 key pairs.
The control plane requires `AUTHORITY_OPERATOR_PUBLIC_KEY_FILE` and accepts an
optional `AUTHORITY_OPERATOR_KEY_ID` (default `operator-key-1`). It never reads the
operator private key and refuses configuration that reuses its own signing key.
Grant signing remains configured with `AUTHORITY_SIGNING_KEY_FILE`.

On the operator workstation, set `AUTHORITY_OPERATOR_KEY_FILE` and the matching
key ID before running `authority-admin`. Publish only the public key to each
control-plane replica. A control-plane-signed administration command is rejected.

For the local demonstration, `scripts/run-poc.sh` invokes
`scripts/prepare-operator-key.sh`, which creates a dedicated pair in `.secrets/`
with private permissions. It refuses incomplete or mismatched existing pairs.
With an explicitly configured operator public-key file, it generates no local
pair. Keeping both private keys on one development workstation is a demo setup;
the production control-plane configuration needs only the operator public key.

## Delivery status

Authorization rejects targets without a usable revocation delivery origin, with
`enforcement_origin_unavailable` recorded in the policy decision.

Administration responses include `deliveries`, `blocked_receivers`, and
`pending_receivers`. Each target reports one of:

| State | Meaning |
| --- | --- |
| `pending` | A configured target still owes a signed cleanup receipt. |
| `completed` | The enrolled node key authenticated the cleanup receipt. |
| `missing_origin` | An existing grant's target has no delivery origin. |
| `missing_target` | The target registration no longer exists. |
| `expired` | The signed notice's delivery window has elapsed without completion. |

Missing configuration and expired delivery stay visible and keep `completed`
false. `authority-admin` exits immediately with the operation JSON when delivery
is blocked; an unreachable configured receiver retains the bounded pending wait.
Keep the returned operation nonce. After correcting a missing origin, retry with
`AUTHORITY_OPERATION_NONCE` and the same selector and reason to query/reconcile
without advancing the identity generation again. An expired notice requires a
fresh administrative revocation operation; the old operation remains an honest
record of missing acknowledgment. Issuance stays disabled throughout recovery.
