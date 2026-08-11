# EUDI Wallet Simulator

A web based EUDI wallet for testing OID4VP verifiers. There is no issuance and no custom URL
scheme. The verifier's wallet link opens a credential picker in the browser. The simulator answers
with a signed SD-JWT VC presentation. It works with any OID4VP verifier. A ready to run example
with [keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp) is
included.

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

### Registration certificate example

The client_id is the base64url SHA-256 hash of the verifier's signing certificate:

```sh
HASH=$(openssl x509 -in verifier-cert.pem -outform DER \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
curl "http://localhost:8080/api/registration-certificates?client_id=x509_hash:${HASH}&purpose=Login"
```

The response contains the raw certificate and the ready to paste `verifierInfo` value. The
`verifierInfo` member is a JSON array serialized into a string because verifier configuration
fields usually take text. In the request object the claim is the plain array
`[{"format": "registrar_dataset", "data": "…"}]` as required by the amendment to
IR (EU) 2024/2977. The data member is the base64url encoding of the signed registration
certificate:

```json
{
  "registrationCertificate": "eyJ0eXAiOiJyYy1ycCtqd3QiLCJ4NWMiOlsi...",
  "verifierInfo": "[{\"format\":\"registrar_dataset\",\"data\":\"ZXlKMGVYQWlPaUp5WXkxeWND...\"}]"
}
```

For keycloak-extension-oid4vp put the `verifierInfo` string into the `oid4vp` identity provider
configuration:

```json
{
  "alias": "oid4vp",
  "providerId": "oid4vp",
  "config": {
    "verifierInfo": "[{\"format\":\"registrar_dataset\",\"data\":\"ZXlKMGVYQWlPaUp5WXkxeWND...\"}]"
  }
}
```

In the Keycloak admin console the same value goes into the *Verifier Info (JSON)* field of the
`oid4vp` identity provider. The rendered realm in `examples/keycloak/realm-wallet-demo.json`
shows a complete working configuration.

## Using the UI

The home page shows all wallet credentials as cards. You can revoke and activate them, clone one
as a template with *Edit as template*, or create one from scratch with *New credential*. Every
claim is a form field. Nested claims use dot notation, for example address.locality.

During a verification the picker shows one selection group per requested DCQL credential query.
The evaluation covers vct and claim matching, claim_sets in preference order, credential_sets
combinations and trusted_authorities (aki and etsi_tl). Credentials that do not match are not
offered. The answer is a multi entry vp_token when several queries are requested.
*Present credential* answers directly. *Edit & present* clones the selected credential, lets you
change the claims, then issues and presents the edited credential in one step. Every issued
credential gets a fresh holder binding key.

Conformance warnings appear on the picker when the verifier request violates OID4VP or HAIP. In
`strict` mode such requests are refused and the wallet answers the verifier with an
`invalid_request` error response per OID4VP 1.0 §8.5. Cancelling sends `access_denied`. Error
responses are encrypted for `direct_post.jwt`.

## Automating the UI

The UI is server rendered without JavaScript and every interactive element has a stable id.
Playwright and similar frameworks can rely on these selectors.

| Selector | Element |
|---|---|
| `[data-credential-id="<id>"]` | Credential card on the home page and the picker |
| `#select-<id>` | Radio button that selects a credential on the home page |
| `#select-<queryId>-<id>` | Radio button on the picker, one group per DCQL credential query |
| `#present-credential`, `#edit-and-present`, `#cancel-presentation` | Actions on the picker |
| `#edit-as-template`, `#new-credential`, `#toggle-status-<id>` | Actions on the home page |
| `#credential-id`, `#credential-name`, `#credential-vct`, `#validity-days` | Edit form header fields |
| `#claim-<name>` | One input per claim on the edit form. Nested claims use dot notation, for example `claim-address.locality` |
| `#new-claim-name`, `#new-claim-value`, `#add-claim` | Add a claim on the edit form |
| `#issue-credential`, `#cancel-edit` | Edit form actions |
| `#conformance-warnings`, `#form-error` | Warning and error containers |

A full flow needs no fixed waits. Each action is a plain form post and the next page contains the
selectors above.

## Configuration

| Property | Default | Purpose |
|---|---|---|
| `app.base-url` | `http://localhost:8080` | External base URL embedded in issued tokens |
| `app.mode` | `debug` | `debug` warns and continues. `strict` refuses non conformant requests |
| `app.pki.dir` | `data/pki` | PEM directory for the persisted CA, issuer, wallet provider and registrar keys |
| `app.resources.credentials` | `classpath:credentials.yml` | Pre defined credential seed. Any Spring resource works, for example `file:my-credentials.yml` |
| `app.basepath` | *(empty)* | URL prefix when deployed behind a path rewriting ingress |
| `server.port` | `8080` | HTTP port |

Environment variable form: `APP_BASEURL`, `APP_MODE`, `SERVER_PORT`.

Credentials, ad hoc changes and revocations are held in memory and reset on restart. The PKI
persists.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/credentials`, `GET /api/credentials/{id}` | Wallet content with SD-JWT and status |
| `POST /api/credentials/{id}/status` `{"status": 1}` | Revoke with 1, reactivate with 0 |
| `GET /api/credentials/{id}/status` | Current status list value |
| `GET /status-list` | IETF Token Status List (`statuslist+jwt`) |
| `GET /trust-lists/credentials`, `GET /trust-lists/wallet-providers` | ETSI TS 119 602 LoTE JWTs |
| `GET /api/registration-certificates?client_id=…&purpose=…` | Issues an `rc-rp+jwt` and the matching `verifierInfo` value |
| `GET /api/wallet-attestation?client_id=…&aud=…` | OAuth client attestation and PoP pair |
| `GET /api/config` | Effective configuration, for example the conformance mode |

## Development

```sh
mvn verify                    # tests and spotless formatting check
mvn spotless:apply            # format
examples/keycloak/smoke-test.sh   # headless E2E against the Keycloak example
```
