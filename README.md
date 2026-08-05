# EUDI Wallet Simulator

A web based EUDI wallet for testing OID4VP verifiers. There is no issuance and no custom URL
scheme. The verifier's wallet link opens a credential picker in the browser. The simulator answers
with a signed SD-JWT VC presentation. Built for testing
[keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp).

## Quickstart

```sh
mvn spring-boot:run           # http://localhost:8080
```

A ready to run Keycloak verifier setup is in [`examples/keycloak`](examples/keycloak/README.md).

## Connecting your verifier

1. Point the verifier's wallet URL at `http://localhost:8080/authorize`. The verifier appends
   `client_id` and `request_uri`. Only the `x509_hash` client identifier prefix is accepted.
   HAIP mandates it.
2. Configure the trust anchor. The verifier finds the credential issuers in the ETSI TS 119 602
   trust list at `GET /trust-lists/credentials`. Wallet providers are listed at
   `GET /trust-lists/wallet-providers`.
3. Get a registration certificate. Every request must carry `verifier_info`. Call
   `GET /api/registration-certificates?client_id=x509_hash:…` and put the returned `verifierInfo`
   value into the verifier configuration. The registrar key is persisted. The certificate stays
   valid across simulator restarts.

## Using the UI

The home page shows all wallet credentials as cards. You can revoke and activate them, clone one
as a template with *Edit as template*, or create one from scratch with *New credential*. Claims
are edited as raw JSON.

During a verification the picker shows every credential that matches the verifier's DCQL query.
*Present credential* answers directly. *Edit & present* clones the selected credential, lets you
change the claims, then issues and presents the edited credential in one step. Every issued
credential gets a fresh holder binding key.

Conformance warnings appear on the picker when the verifier request violates OID4VP or HAIP. In
`strict` mode such requests are refused instead.

## Configuration

| Property | Default | Purpose |
|---|---|---|
| `app.base-url` | `http://localhost:8080` | External base URL embedded in issued tokens |
| `app.conformance.mode` | `debug` | `debug` warns and continues. `strict` refuses non conformant requests |
| `app.pki.dir` | `data/pki` | PEM directory for the persisted CA, issuer, wallet provider and registrar keys |
| `app.resources.credentials` | `classpath:credentials.yml` | Pre defined credential seed. Any Spring resource works, for example `file:my-credentials.yml` |
| `app.basepath` | *(empty)* | URL prefix when deployed behind a path rewriting ingress |
| `server.port` | `8080` | HTTP port |

Environment variable form: `APP_BASEURL`, `APP_CONFORMANCE_MODE`, `SERVER_PORT`.

Credentials, ad hoc changes and revocations are held in memory and reset on restart. The PKI
persists.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/credentials`, `GET /api/credentials/{id}` | Wallet content with SD-JWT and status |
| `POST /api/credentials/{id}/status` `{"status": 1}` | Revoke with 1, reactivate with 0, or set any status type |
| `GET /api/credentials/{id}/status` | Current status list value |
| `GET /status-list` | IETF Token Status List (`statuslist+jwt`) |
| `GET /trust-lists/credentials`, `GET /trust-lists/wallet-providers` | ETSI TS 119 602 LoTE JWTs |
| `GET /api/registration-certificates?client_id=…&purpose=…` | Issues an `rc-rp+jwt` and the matching `verifierInfo` value |
| `GET /api/wallet-attestation?client_id=…&aud=…` | OAuth client attestation and PoP pair |
| `GET /api/config`, `PUT /api/config/conformance` `{"mode":"strict"}`, `DELETE …/conformance` | Conformance mode at runtime |
| `GET /api/log`, `DELETE /api/log` | Activity log of all protocol interactions |

## Development

```sh
mvn verify                    # tests and spotless formatting check
mvn spotless:apply            # format
examples/keycloak/smoke-test.sh   # headless E2E against the Keycloak example
```
