# Authority PoC

This workspace demonstrates the initial end-to-end trust flow:

1. authenticate a human with a Passkey;
2. evaluate an explicit user, device, target, and principal policy;
3. sign a versioned issuance-authorization contract in the Control Plane;
4. independently verify that contract in the Credential Issuer;
5. bind it to a locally generated SSH public key and issue a five-minute
   OpenSSH user certificate;
6. verify the CA signature and install the certificate in the Node Agent.

PostgreSQL runs in the `authority-db` LXC container. Start the privileged
database agent first if it is not already running:

```sh
mise run agent:serve
```

In another terminal, start the complete PoC:

```sh
mise run poc:run
```

Open the bootstrap URL printed by the runner. Use **Create user and Passkey**
once, then **Sign in with Passkey**. A successful run prints the local SSH key
and certificate paths together with the issued OpenSSH certificate.

## Testing without Passkey hardware

Chromium DevTools provides a software WebAuthn authenticator which still runs
the real browser WebAuthn ceremony:

1. open DevTools on the PoC page;
2. press `Ctrl+Shift+P`, enter `WebAuthn`, and select **Show WebAuthn**;
3. enable **Enable virtual authenticator environment**;
4. add an authenticator with protocol **CTAP2**, transport **internal**, and
   **Supports user verification** enabled;
5. return to the page and create the Passkey.

Keep that DevTools session open while registering and signing in so the same
virtual credential remains available.

## Connecting from another machine

The three PoC services bind to loopback on ports 3000, 3001, and 3002. They are
deliberately not exposed as plaintext HTTP services on the LAN: doing so would
leak bootstrap and session material, and a raw LAN origin is not a WebAuthn
secure context.

For a browser running on another machine, forward all three ports and continue
to use the `localhost` URL:

```sh
ssh \
  -L 3000:127.0.0.1:3000 \
  -L 3001:127.0.0.1:3001 \
  -L 3002:127.0.0.1:3002 \
  <authority-machine-ip>
```

Then open the bootstrap `http://localhost:3000/#bootstrap=...` URL in the local
browser. A production-style LAN hostname requires HTTPS and matching
`AUTHORITY_RP_ID` / `AUTHORITY_RP_ORIGIN` values.

All private keys and bootstrap secrets are generated under `.secrets/`, which
is ignored by Git. Stop the PoC with `Ctrl-C`.

Run the checks with:

```sh
mise run test
cargo clippy --workspace --all-targets -- -D warnings
```

With matching `chromium` and `chromedriver` packages installed, the browser
flow can be exercised headlessly with a WebDriver virtual authenticator:

```sh
mise run poc:e2e
```
