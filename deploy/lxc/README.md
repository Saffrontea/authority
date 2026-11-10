# PostgreSQL development container

`authority-db.conf` defines a 512 MiB, two-vCPU, root-managed LXC container
for the PoC database. It uses the host-local `lxcbr0` bridge and is not meant
to be exposed on a public interface.

## Host prerequisite

Container creation must run in the host namespace through the delegated root
agent. Verify the bridge before creating it:

```sh
ip link show lxcbr0
```

## Create and start

If no password source is configured, `agent:serve` generates a development
password at `.secrets/authority-db-password` with mode 0600. The directory is
ignored by git. To use an existing secret manager instead, export it before
starting the agent:

```sh
export AUTHORITY_DB_PASSWORD="$(your-secret-command)"
```

To persist a value in the ignored local mise configuration without putting it
on the command line, pipe it from the secret source:

```sh
your-secret-command | \
  mise set --file mise.local.toml --stdin AUTHORITY_DB_PASSWORD
chmod 600 mise.local.toml
```

Alternatively, set `AUTHORITY_DB_PASSWORD_FILE` to a one-line secret file.
The script does not print the value or pass it as a process argument.

Start the privileged task agent once from a real terminal:

```sh
mise run agent:serve
```

This performs one sudo authentication and then remains in the foreground.
Leave that terminal open while working. The agent exposes only the internal
`_db:*` and `_mesh:*` task allowlists, accepts connections only from the launching user via
`SO_PEERCRED`, and does not accept caller-provided arguments or environment
variables.

In another terminal—or from an automation agent—run the complete setup:

```sh
mise run db:setup
```

The public `db:*` tasks delegate to the root agent over a mode-0600 Unix
socket. A same-user filesystem queue bridge is started alongside it so
restricted sandboxes that cannot call `connect(2)` can still delegate. Public
tasks do not invoke sudo or wait for a password. Stop the agent with Ctrl-C in
its terminal when privileged delegation is no longer needed.

The task creates and starts the container, installs PostgreSQL, restricts
network authentication to the host bridge address, and creates the
`authority` role and database. Re-running it also reconciles the role password
with the current environment value.

Individual lifecycle tasks are also available:

```sh
mise run db:create
mise run db:start
mise run db:install
mise run db:migrate
mise run db:status
mise run db:verify
mise run db:verify-schema
mise run db:shell
mise run db:reset-password
mise run db:stop
mise run db:destroy
```

`db:shell` and `db:destroy` intentionally bypass the agent because they are
interactive or destructive; they still require direct sudo authentication.

Agent health and the exposed task list can be inspected with:

```sh
mise run agent:ping
mise run agent:list
```

The setup script detects the host architecture. The container is root-managed
like the LXC test environment in `rust-ebpf`; do not run untrusted workloads
inside it.

Keep the password outside the repository. The application should receive the
connection string through its local secret/environment configuration.

## WireGuard mesh proof

The mesh task creates two small root-managed LXC nodes. Their `eth0` devices
use `lxcbr0` only as an underlay; `wg0` uses `10.77.0.1/32` and
`10.77.0.2/32`. Each private key remains inside its own container.

After changing the agent allowlist, restart `agent:serve` once, then run:

```sh
mise run mesh:setup
```

The setup is idempotent and ends by pinging the target over `wg0` and checking
for a non-zero WireGuard handshake timestamp. Useful lifecycle tasks are:

```sh
mise run mesh:status
mise run mesh:verify
mise run mesh:stop
mise run mesh:start
mise run mesh:configure
mise run mesh:destroy
```

`mesh:start` reads the containers' current DHCP addresses and reconciles both
WireGuard endpoints, so the tunnel survives an LXC stop/start cycle even when
the `lxcbr0` underlay addresses change.

`mesh:destroy` is interactive and intentionally bypasses the agent. This first
slice proves the encrypted network substrate; policy is still static until a
signed, short-lived Network Grant is wired into the node agent.

The signed-grant slice installs `authority-network-agent` in the target node:

```sh
mise run mesh:agent:install
mise run mesh:agent:status
```

The install task reads the target node identity from the ignored local file
`.secrets/poc-mesh-target-node-id`. The browser E2E writes that value from the
bootstrap response. On startup the agent clears peers from its dedicated `wg0`
interface (fail closed), then admits only peers carried by a valid, unexpired
`NetworkAccessGrantV1` for its own node ID. Each peer is removed at expiry; a
newer grant for the same peer supersedes the older expiry timer.

`mise run poc:e2e` exercises Passkey authentication, SSH issuance, network
grant issuance and application, then waits for the five-second test grant to
expire and proves that the tunnel is denied before restoring the development
mesh.
