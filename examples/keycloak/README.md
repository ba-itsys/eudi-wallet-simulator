# Keycloak example

Runs a real [keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp)
verifier against this wallet simulator. The setup downloads release 0.9.0 of the extension from
Maven Central, override it with EXTENSION_VERSION when running setup.sh. A jar placed next to
setup.sh is used as is, which is how a locally built snapshot goes in.

## Layout

Keycloak runs in Docker on port 8080 with the imported `wallet-demo` realm. The realm configures
the `oid4vp` identity provider with HAIP settings (`x509_hash`, `direct_post.jwt`) and a wallet
URL of `http://localhost:8081/authorize`. That is a plain web URL without a custom scheme. An
`etsi-trust-list` identity provider points at the simulator's credentials trust list.

The simulator runs on the host on port 8081. Its base URL is `host.docker.internal:8081` so
Keycloak can fetch the trust list and the status list from inside the container.

## Run it

```sh
# 1. Start the simulator (from the repository root)
SERVER_PORT=8081 APP_BASEURL=http://host.docker.internal:8081 mvn spring-boot:run

# 2. Download the extension jar, create the verifier certificate,
#    fetch a registration certificate from the simulator, render the realm
./setup.sh

# 3. Start Keycloak
docker compose up -d
```

Open <http://localhost:8080/realms/wallet-demo/account/> and choose **Sign in with Wallet**, then
**Open wallet**. The browser lands on the simulator's credential picker. Present a credential and
the login completes with the disclosed claims mapped to the Keycloak user.

The realm requests a PID and a health insurance credential as one credential set with two
options, `[["pid", "ehic"], ["pid"]]`. The verifier therefore accepts the PID together with the
health insurance credential, or the PID alone, and the picker lets you choose which of the two
combinations to answer with. Both credential types are part of the simulator's default wallet
content.

Every credential query also carries `trusted_authorities` entries: `etsi_tl` pointing at the
simulator's credentials trust list and `aki` with the key identifiers of its issuer certificates.
The wallet therefore only offers credentials whose issuer is anchored there. The entries come
from the `etsi-trust-list` identity provider, which advertises its trust domain on every
credential it serves.

The realm configures this verbatim in DCQL syntax on the `oid4vp` identity provider:

```json
"credentialSets": "[{\"options\": [[\"pid\", \"ehic\"], [\"pid\"]]}]",
"principalAttributes": "pid:family_name"
```

The mappers name their credential with `credential.id`, which is what the options refer to.
`principalAttributes` says which claim of which credential identifies the user, so the PID's
`family_name` becomes the Keycloak username. Both settings need extension 0.9.0 or newer.

The extension matches credential types exactly, so it refuses a credential whose vct only inherits
from the requested one. Presenting Thomas or Erika for a query asking `urn:eudi:pid:1` therefore
fails at the verifier, and the simulator shows the verifier's reason on its error page.

The admin console is at <http://localhost:8080/admin> with user `admin` and password `admin`.

## Trying revocation

```sh
# Revoke Maria's PID. The verifier checks the status list on every login.
curl -X POST http://localhost:8081/api/credentials/pid-maria-neumann/status \
  -H 'Content-Type: application/json' -d '{"status": 1}'
```

The next login with that credential fails at the verifier. Reactivate with `{"status": 0}`.

## Smoke test

`./smoke-test.sh` drives the full same device login headlessly with curl and prints PASS or FAIL.
