#!/bin/sh
# Headless same-device login through the real keycloak-extension-oid4vp verifier and the
# wallet simulator, using curl only. Requires: setup.sh done, docker compose up, simulator
# running on port 8081 with APP_BASEURL=http://host.docker.internal:8081.
set -eu

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
SIMULATOR_URL="${SIMULATOR_URL:-http://localhost:8081}"
WORK_DIR="$(mktemp -d)"
COOKIES="${WORK_DIR}/cookies.txt"
trap 'rm -rf "$WORK_DIR"' EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

echo "1/5 Opening Keycloak account console login..."
LOGIN_PAGE=$(curl -sSL -c "$COOKIES" -b "$COOKIES" \
  "${KEYCLOAK_URL}/realms/wallet-demo/protocol/openid-connect/auth?client_id=account-console&redirect_uri=${KEYCLOAK_URL}/realms/wallet-demo/account/&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256" \
  | tr '\n' ' ')
IDP_LINK=$(printf '%s' "$LOGIN_PAGE" | grep -o 'id="social-oid4vp"[^>]*' | grep -o 'href="[^"]*"' | head -1 | sed 's/href="//;s/"$//' | sed 's/&amp;/\&/g')
[ -n "$IDP_LINK" ] || fail "no social-oid4vp link on the login page"

echo "2/5 Following the wallet identity provider..."
WALLET_PAGE=$(curl -sSL -c "$COOKIES" -b "$COOKIES" "${KEYCLOAK_URL}${IDP_LINK}" | tr '\n' ' ')
WALLET_URL=$(printf '%s' "$WALLET_PAGE" | grep -o 'id="oid4vp-open-wallet"[^>]*' | grep -o 'href="[^"]*"' | head -1 | sed 's/href="//;s/"$//' | sed 's/&amp;/\&/g')
[ -n "$WALLET_URL" ] || fail "no oid4vp-open-wallet link on the wallet page"
case "$WALLET_URL" in
  "${SIMULATOR_URL}/authorize"*) ;;
  *) fail "wallet URL does not point at the simulator: $WALLET_URL" ;;
esac

echo "3/5 Opening the simulator credential picker..."
PICKER=$(curl -sS "$WALLET_URL" | tr '\n' ' ')
printf '%s' "$PICKER" | grep -q 'data-credential-id="pid-jan-hart"' || fail "picker does not offer the PID credential"
FLOW_STATE=$(printf '%s' "$PICKER" | grep -o 'name="flowState" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
[ -n "$FLOW_STATE" ] || fail "no flowState on the picker page"

# the realm requests a credential set, answer with its first option and every query it contains
SET_OPTION=$(printf '%s' "$PICKER" | tr '<' '\n' | grep '^option .*data-query-ids=' | head -1 \
  | grep -o 'value="[0-9]*"' | head -1 | tr -dc '0-9')
QUERY_IDS=$(printf '%s' "$PICKER" | tr '<' '\n' | grep '^option .*data-query-ids=' | head -1 \
  | sed 's/.*data-query-ids="//;s/".*//' | tr ',' ' ')
[ -n "$QUERY_IDS" ] || fail "no credential set option on the picker"

SELECTIONS=""
for QUERY_ID in $QUERY_IDS; do
  CREDENTIAL_ID=$(printf '%s' "$PICKER" | grep -o "id=\"select-${QUERY_ID}-[^\"]*\"" | head -1 \
    | sed "s/id=\"select-${QUERY_ID}-//;s/\"$//")
  [ -n "$CREDENTIAL_ID" ] || fail "no credential offered for query ${QUERY_ID}"
  SELECTIONS="${SELECTIONS} --data-urlencode selection[${QUERY_ID}]=${CREDENTIAL_ID}"
done

echo "4/5 Presenting the credentials for ${QUERY_IDS}..."
# shellcheck disable=SC2086
REDIRECT=$(curl -sS -o /dev/null -w '%{redirect_url}' \
  ${SELECTIONS} \
  --data-urlencode "setOption[0]=${SET_OPTION}" \
  --data-urlencode "flowState=${FLOW_STATE}" \
  "${SIMULATOR_URL}/authorize/submit")
case "$REDIRECT" in
  "${KEYCLOAK_URL}"*complete-auth*) ;;
  *) fail "submit did not redirect to the verifier complete-auth URL: '$REDIRECT'" ;;
esac

echo "5/5 Completing the login in the browser session..."
FINAL_URL=$(curl -sSL -c "$COOKIES" -b "$COOKIES" -o "${WORK_DIR}/final.html" -w '%{url_effective}' "$REDIRECT")
case "$FINAL_URL" in
  *"/realms/wallet-demo/account"*) ;;
  *) grep -qi "update account information\|firstBrokerLogin" "${WORK_DIR}/final.html" \
      || fail "login did not reach the account console or first-broker-login page: $FINAL_URL" ;;
esac

echo "PASS: full same-device login flow via keycloak-extension-oid4vp succeeded."
