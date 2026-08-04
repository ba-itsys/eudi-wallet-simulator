# EUDI Wallet Simulator

Web-based EUDI wallet simulator for testing OID4VP verifiers — no issuance, no custom URL
schemes. A verifier's wallet link (`/authorize?client_id=…&request_uri=…`) opens a credential
picker in the browser; the simulator answers with a fully signed SD-JWT VC presentation and
reports (or enforces) verifier conformance along the way.

Built for testing [keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp);
see [`examples/keycloak`](examples/keycloak/README.md) for a ready-to-run setup.

## Features

- **OID4VP wallet** (same-device and cross-device): request object via `request_uri`,
  DCQL matching, SD-JWT VC presentations with KB-JWT, `direct_post` and `direct_post.jwt`
  (JWE-encrypted) responses. Client identifier prefix: `x509_hash` only (HAIP).
- **Verifier conformance checking** in two modes — `debug` (default) collects findings and shows
  them as warnings while the flow continues; `strict` refuses non-conformant requests. Switch at
  runtime via `PUT /api/config/conformance {"mode": "strict"}`.
- **EUDI registration certificates**: requests must carry `verifier_info` with a registration certificate
  (`rc-rp+jwt`) issued by this wallet's registrar — generate one via
  `GET /api/registration-certificates?client_id=…` (response contains the ready-to-paste
  `verifierInfo` value). The registrar key is persisted, so certificates stay valid across
  restarts.
- **Pre-defined credentials** seeded from [`credentials.yml`](src/main/resources/credentials.yml)
  (override with `app.resources.credentials`), plus ad-hoc credentials created in the UI — from
  scratch or by cloning an existing one as template, with a raw JSON claims editor.
- **ETSI TS 119 602 trust lists**: `/trust-lists/credentials` (PID providers) and
  `/trust-lists/wallet-providers`, consumable by the `etsi-trust-list` Keycloak identity
  provider.
- **Token status list + revocation**: every credential has a stable id and status index;
  `/status-list` serves the `statuslist+jwt`; revoke with
  `POST /api/credentials/{id}/status {"status": 1}`.
- **Wallet attestation**: `GET /api/wallet-attestation?client_id=…&aud=…` returns an
  `oauth-client-attestation+jwt` and PoP pair anchored via the wallet-providers trust list.

## Running

```sh
mvn spring-boot:run           # http://localhost:8080
```

Key configuration (`application.yaml` or environment):

| Property | Default | Purpose |
|---|---|---|
| `app.base-url` | `http://localhost:8080` | External base URL embedded in issued tokens |
| `app.conformance.mode` | `debug` | `debug` warns, `strict` refuses |
| `app.pki.dir` | `data/pki` | Persisted CA/issuer/registrar/holder key material |
| `app.resources.credentials` | `classpath:credentials.yml` | Pre-defined credential seed |
| `app.basepath` | *(empty)* | URL prefix when deployed behind a path-rewriting ingress |

The activity log of all protocol interactions is on `GET /api/log`.

## Development

```sh
mvn verify                    # tests + spotless formatting check
mvn spotless:apply            # format
```
