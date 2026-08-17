#!/bin/sh
# Prepares the Keycloak example: downloads the keycloak-extension-oid4vp jar, generates a
# verifier signing certificate (SAN DNS localhost), and renders the realm import file.
# Afterwards: docker compose up, and start the simulator on port 8081.
set -eu

EXAMPLE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
EXTENSION_VERSION="${EXTENSION_VERSION:-0.9.1}"
EXTENSION_JAR="${EXAMPLE_DIR}/keycloak-extension-oid4vp.jar"
EXTENSION_URL="https://repo1.maven.org/maven2/de/arbeitsagentur/opdt/keycloak-extension-oid4vp/${EXTENSION_VERSION}/keycloak-extension-oid4vp-${EXTENSION_VERSION}.jar"

if [ ! -f "$EXTENSION_JAR" ]; then
  echo "Downloading keycloak-extension-oid4vp ${EXTENSION_VERSION}..."
  curl -sfL "$EXTENSION_URL" -o "$EXTENSION_JAR" || {
    echo "Could not download ${EXTENSION_URL}" >&2
    echo "If the release is not out yet, build the jar from a keycloak-extension-oid4vp checkout" >&2
    echo "with 'mvn -pl core package -DskipTests' and copy core/target/keycloak-extension-oid4vp.jar" >&2
    echo "next to this script." >&2
    exit 1
  }
fi

SIMULATOR_URL="${SIMULATOR_URL:-http://localhost:8081}"
if ! curl -sf "${SIMULATOR_URL}/livez" >/dev/null 2>&1; then
  echo "The wallet simulator must be running (it issues the registration certificate)." >&2
  echo "Start it first: SERVER_PORT=8081 APP_BASEURL=http://host.docker.internal:8081 \\" >&2
  echo "  APP_PKI_SEED=wallet-simulator-keycloak-example mvn spring-boot:run" >&2
  exit 1
fi

if [ ! -f "${EXAMPLE_DIR}/verifier-key.pem" ]; then
  echo "Generating verifier CA and CA-issued signing certificate (HAIP)..."
  openssl ecparam -name prime256v1 -genkey -noout -out "${EXAMPLE_DIR}/verifier-ca-key.pem"
  openssl req -new -x509 -key "${EXAMPLE_DIR}/verifier-ca-key.pem" \
    -subj "/CN=Wallet Simulator Example Verifier CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -days 365 -out "${EXAMPLE_DIR}/verifier-ca-cert.pem"
  openssl ecparam -name prime256v1 -genkey -noout -out "${EXAMPLE_DIR}/verifier-key.pem"
  openssl req -new -key "${EXAMPLE_DIR}/verifier-key.pem" -subj "/CN=localhost" \
    -out "${EXAMPLE_DIR}/verifier.csr"
  printf 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' \
    > "${EXAMPLE_DIR}/verifier-ext.cnf"
  openssl x509 -req -in "${EXAMPLE_DIR}/verifier.csr" \
    -CA "${EXAMPLE_DIR}/verifier-ca-cert.pem" -CAkey "${EXAMPLE_DIR}/verifier-ca-key.pem" \
    -CAcreateserial -days 365 -extfile "${EXAMPLE_DIR}/verifier-ext.cnf" \
    -out "${EXAMPLE_DIR}/verifier-cert.pem" 2>/dev/null
  rm -f "${EXAMPLE_DIR}/verifier.csr" "${EXAMPLE_DIR}/verifier-ext.cnf" "${EXAMPLE_DIR}/verifier-ca-cert.srl"
  # the extension expects a PKCS#8 "PRIVATE KEY" block in the combined PEM
  openssl pkcs8 -topk8 -nocrypt -in "${EXAMPLE_DIR}/verifier-key.pem" -out "${EXAMPLE_DIR}/verifier-key-pkcs8.pem"
  cat "${EXAMPLE_DIR}/verifier-cert.pem" "${EXAMPLE_DIR}/verifier-ca-cert.pem" "${EXAMPLE_DIR}/verifier-key-pkcs8.pem" \
    > "${EXAMPLE_DIR}/verifier-combined.pem"
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
