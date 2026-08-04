# Keycloak example

Runs a real [keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp)
verifier (locally built snapshot jar from the sibling checkout) against this wallet simulator.

## Layout

- Keycloak runs in Docker on port **8080** with the `wallet-demo` realm imported. The realm
  configures the `oid4vp` identity provider (x509_san_dns, direct_post) with
  `walletScheme = http://localhost:8081/authorize` — a plain web URL, no custom URL scheme —
  and an `etsi-trust-list` identity provider pointing at the simulator's credentials trust list.
- The simulator runs on the host on port **8081**. Its base URL is `host.docker.internal:8081`
  so Keycloak can fetch the trust list and the status list from inside the container.

## Run it

```sh
# 1. Build the extension jar (if needed), generate the verifier certificate, render the realm
./setup.sh

# 2. Start Keycloak
docker compose up -d

# 3. Start the simulator (from the repository root)
SERVER_PORT=8081 APP_BASEURL=http://host.docker.internal:8081 mvn spring-boot:run
```

Open <http://localhost:8080/realms/wallet-demo/account/>, choose **Sign in with Wallet**, then
**Open wallet** — the browser lands on the simulator's credential picker. Present a PID
credential and the login completes with the disclosed claims mapped to the Keycloak user.

## Trying revocation

```sh
# Revoke Maria's PID (the verifier checks the status list on every login)
curl -X POST http://localhost:8081/api/credentials/pid-maria-neumann/status \
  -H 'Content-Type: application/json' -d '{"status": 1}'
```

The next login with that credential fails at the verifier. Reactivate with `{"status": 0}`.

## Smoke test

`./smoke-test.sh` drives the full same-device login headlessly (curl only) and prints PASS/FAIL.
