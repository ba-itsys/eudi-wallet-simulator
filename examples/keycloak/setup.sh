#!/bin/sh
# Prepares the Keycloak example: builds the keycloak-extension-oid4vp snapshot jar from the
# sibling checkout, generates a verifier signing certificate (SAN DNS localhost), and renders
# the realm import file. Afterwards: docker compose up, and start the simulator on port 8081.
set -eu

EXAMPLE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
EXTENSION_DIR="${EXTENSION_DIR:-${EXAMPLE_DIR}/../../../keycloak-extension-oid4vp}"
EXTENSION_JAR="${EXTENSION_DIR}/core/target/keycloak-extension-oid4vp.jar"

if [ ! -d "$EXTENSION_DIR" ]; then
  echo "keycloak-extension-oid4vp checkout not found at ${EXTENSION_DIR}" >&2
  echo "Clone it next to this repository or set EXTENSION_DIR." >&2
  exit 1
fi

if [ ! -f "$EXTENSION_JAR" ]; then
  echo "Building keycloak-extension-oid4vp snapshot jar..."
  mvn -f "${EXTENSION_DIR}/pom.xml" -pl core -am package -DskipTests -q
fi

SIMULATOR_URL="${SIMULATOR_URL:-http://localhost:8081}"
if ! curl -sf "${SIMULATOR_URL}/livez" >/dev/null 2>&1; then
  echo "The wallet simulator must be running (it issues the registration certificate)." >&2
  echo "Start it first: SERVER_PORT=8081 APP_BASEURL=http://host.docker.internal:8081 mvn spring-boot:run" >&2
  exit 1
fi

if [ ! -f "${EXAMPLE_DIR}/verifier-key.pem" ]; then
  echo "Generating verifier signing certificate..."
  openssl ecparam -name prime256v1 -genkey -noout -out "${EXAMPLE_DIR}/verifier-key.pem"
  openssl req -new -x509 -key "${EXAMPLE_DIR}/verifier-key.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
    -days 365 -out "${EXAMPLE_DIR}/verifier-cert.pem"
  cat "${EXAMPLE_DIR}/verifier-cert.pem" "${EXAMPLE_DIR}/verifier-key.pem" > "${EXAMPLE_DIR}/verifier-combined.pem"
fi

CERT_HASH=$(openssl x509 -in "${EXAMPLE_DIR}/verifier-cert.pem" -outform DER \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
CLIENT_ID="x509_hash:${CERT_HASH}"

echo "Requesting registration certificate for ${CLIENT_ID}..."
VERIFIER_INFO=$(curl -sf "${SIMULATOR_URL}/api/registration-certificates?client_id=$(printf '%s' "$CLIENT_ID" | sed 's/:/%3A/g')&purpose=Keycloak%20example%20login" \
  | perl -0ne 'print $1 if /"verifierInfo":"((?:[^"\\]|\\.)*)"/')
if [ -z "$VERIFIER_INFO" ]; then
  echo "Could not obtain a registration certificate from ${SIMULATOR_URL}" >&2
  exit 1
fi

PEM_CONTENT=$(sed 's/$/\\n/' "${EXAMPLE_DIR}/verifier-combined.pem" | tr -d '\n' | sed 's/\\n$//')
export PEM_CONTENT VERIFIER_INFO
perl -pe 's/__VERIFIER_PEM__/$ENV{PEM_CONTENT}/; s/__VERIFIER_INFO__/$ENV{VERIFIER_INFO}/' \
  "${EXAMPLE_DIR}/realm-wallet-demo.json.template" > "${EXAMPLE_DIR}/realm-wallet-demo.json"

echo ""
echo "Done. Next steps:"
echo "  1. docker compose -f ${EXAMPLE_DIR}/docker-compose.yml up -d"
echo "  2. Open http://localhost:8080/realms/wallet-demo/account/ and choose 'Sign in with Wallet'."
