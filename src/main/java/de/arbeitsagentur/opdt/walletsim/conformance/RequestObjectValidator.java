package de.arbeitsagentur.opdt.walletsim.conformance;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.oid4vp.AuthorizationRequest;
import de.arbeitsagentur.opdt.walletsim.oid4vp.ClientMetadataKeys;
import de.arbeitsagentur.opdt.walletsim.oid4vp.RequestObjectRetrieval;
import de.arbeitsagentur.opdt.walletsim.registrar.RegistrationCertificateService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Collects verifier conformance findings against OpenID4VP 1.0 plus the EUDI requirement
 * that verifier_info carries a registration certificate accepted by this wallet's registrar.
 * Findings are always collected in full; whether they warn or refuse is the caller's mode
 * decision (ADR: debug-by-default validation).
 */
@Component
public class RequestObjectValidator {

    private static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    private final RegistrationCertificateService registrationCertificates;

    public RequestObjectValidator(RegistrationCertificateService registrationCertificates) {
        this.registrationCertificates = registrationCertificates;
    }

    public List<Finding> validate(
            String queryClientId, AuthorizationRequest request, RequestObjectRetrieval retrieval) {
        List<Finding> findings = new ArrayList<>();
        SignedJWT jwt = parse(request.rawRequestObject());

        validateRetrieval(retrieval, request, findings);

        if (jwt.getHeader().getType() == null
                || !REQUEST_OBJECT_TYP.equals(jwt.getHeader().getType().toString())) {
            findings.add(new Finding("Request object typ header must be '" + REQUEST_OBJECT_TYP
                    + "' (OID4VP 1.0 §5.10), got: " + jwt.getHeader().getType()));
        }
        if (request.clientId() == null) {
            findings.add(new Finding("Request object is missing the client_id claim (OID4VP 1.0 §5.1)"));
        } else if (queryClientId != null && !queryClientId.equals(request.clientId())) {
            findings.add(new Finding("client_id in the wallet invocation URL ('" + queryClientId
                    + "') does not match the request object client_id ('" + request.clientId() + "')"));
        }
        if (request.nonce() == null) {
            findings.add(new Finding("Required parameter nonce is missing (OID4VP 1.0 §5.2)"));
        }
        if (!"vp_token".equals(request.responseType())) {
            findings.add(
                    new Finding("response_type must be 'vp_token' (OID4VP 1.0 §5.1), got: " + request.responseType()));
        }
        validateResponseMode(request, findings);
        validateClientIdPrefix(jwt, request, findings);
        validateDcqlStructure(request, findings);
        validateVerifierInfo(jwt, findings);
        validateRequestObjectClaims(jwt, findings);
        validateClientMetadata(request, findings);
        return findings;
    }

    // checks tied to how the request object was fetched
    private static void validateRetrieval(
            RequestObjectRetrieval retrieval, AuthorizationRequest request, List<Finding> findings) {
        if (retrieval.unknownMethod()) {
            findings.add(new Finding("request_uri_method '" + retrieval.requestUriMethod()
                    + "' is not defined by OID4VP 1.0 §5.1, the request object was fetched with GET"));
        }
        if (retrieval.sentWalletNonce() != null && !retrieval.sentWalletNonce().equals(request.walletNonce())) {
            findings.add(
                    new Finding(
                            request.walletNonce() == null
                                    ? "The request object does not echo the posted wallet_nonce as a wallet_nonce claim (OID4VP 1.0 §5.10.1)"
                                    : "The request object wallet_nonce claim does not match the posted wallet_nonce (OID4VP 1.0 §5.10.1)"));
        }
        if (retrieval.encryptionRequested() && !retrieval.encrypted()) {
            findings.add(
                    new Finding(
                            "The wallet asked for an encrypted request object via wallet_metadata.jwks but received an unencrypted one (OID4VP 1.0 §5.10)"));
        }
    }

    private static void validateRequestObjectClaims(SignedJWT jwt, List<Finding> findings) {
        try {
            Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();
            List<String> audience = jwt.getJWTClaimsSet().getAudience();
            if (!audience.contains("https://self-issued.me/v2")) {
                findings.add(new Finding(
                        "Request object aud must be https://self-issued.me/v2 for static discovery (OID4VP 1.0 §5.8), got: "
                                + (audience.isEmpty() ? "no aud claim" : audience)));
            }
            if (jwt.getJWTClaimsSet().getExpirationTime() != null
                    && jwt.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
                findings.add(new Finding("Request object is expired (exp in the past)"));
            }
            if (claims.get("redirect_uri") != null) {
                findings.add(
                        new Finding(
                                "redirect_uri must not be present with response_uri and direct_post response modes (OID4VP 1.0 §8.2)"));
            }
            if (claims.get("transaction_data") != null) {
                findings.add(
                        new Finding(
                                "transaction_data is not supported by this wallet and must be rejected (OID4VP 1.0 §5.1, error invalid_transaction_data)"));
            }
        } catch (ParseException e) {
            findings.add(new Finding("Request object claims cannot be read: " + e.getMessage()));
        }
    }

    private static void validateClientMetadata(AuthorizationRequest request, List<Finding> findings) {
        Map<String, Object> clientMetadata = request.clientMetadata();
        if (clientMetadata == null || !(clientMetadata.get("vp_formats_supported") instanceof Map<?, ?> formats)) {
            findings.add(new Finding("client_metadata must contain vp_formats_supported (OID4VP 1.0 §5.1)"));
            return;
        }
        if (!formats.containsKey("dc+sd-jwt")) {
            findings.add(
                    new Finding(
                            "vp_formats_supported does not include dc+sd-jwt, the only format this wallet presents (OID4VP 1.0 §8.5 vp_formats_not_supported)"));
        }
    }

    private void validateVerifierInfo(SignedJWT jwt, List<Finding> findings) {
        Object verifierInfo;
        try {
            verifierInfo = jwt.getJWTClaimsSet().getClaim("verifier_info");
        } catch (ParseException e) {
            findings.add(new Finding("verifier_info cannot be read: " + e.getMessage()));
            return;
        }
        if (verifierInfo == null) {
            findings.add(
                    new Finding("verifier_info with a registration certificate is required (EUDI, OID4VP 1.0 §5.11)"));
            return;
        }
        if (!(verifierInfo instanceof List<?> attestations) || attestations.isEmpty()) {
            findings.add(new Finding("verifier_info must be a non-empty array of attestations (OID4VP 1.0 §5.11)"));
            return;
        }
        for (Object entry : attestations) {
            if (!(entry instanceof Map<?, ?> attestation)
                    || !("registration_cert".equals(attestation.get("format")))
                    || !(attestation.get("data") instanceof String data)) {
                findings.add(new Finding("Every verifier_info entry needs format 'registration_cert' and string"
                        + " 'data' (ETSI TS 119 472-2, OID4VP 1.0 §5.1)"));
                continue;
            }
            if (attestation.get("credential_ids") != null) {
                findings.add(
                        new Finding(
                                "The registration_cert verifier_info entry must not contain credential_ids (IR (EU) 2024/2977)"));
            }
            registrationCertificates
                    .validate(decodeRegistrationCertificate(data))
                    .ifPresent(violation -> findings.add(new Finding("verifier_info: " + violation)));
        }
    }

    // Deployments disagree on how the certificate travels in data. ETSI TS 119 472-2 reads as
    // base64url of the serialized certificate, while the SPRIND sandbox and other verifiers send
    // the compact rc-wrp+jwt. A wallet under test meets both, so both are accepted
    private static String decodeRegistrationCertificate(String data) {
        if (data.contains(".")) {
            return data;
        }
        try {
            return new String(new Base64URL(data).decode(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return data;
        }
    }

    private static void validateResponseMode(AuthorizationRequest request, List<Finding> findings) {
        String responseMode = request.responseMode();
        if (!"direct_post.jwt".equals(responseMode)) {
            findings.add(
                    new Finding("response_mode must be direct_post.jwt, HAIP 1.0 §5 requires response encryption, got: "
                            + responseMode));
            return;
        }
        if (request.responseUri() == null
                || !(request.responseUri().startsWith("http://")
                        || request.responseUri().startsWith("https://"))) {
            findings.add(new Finding(
                    "response_uri must be an absolute http(s) URL (OID4VP 1.0 §8.2), got: " + request.responseUri()));
        }
        List<Map<String, Object>> keys = ClientMetadataKeys.encryptionKeys(request.clientMetadata());
        if (keys.isEmpty()) {
            findings.add(
                    new Finding(
                            "response_mode direct_post.jwt requires a usable EC encryption key in client_metadata.jwks (OID4VP 1.0 §8.3)"));
        }
        if (keys.stream().anyMatch(key -> key.get("kid") == null)) {
            findings.add(new Finding("Every key in client_metadata.jwks must have a kid (OID4VP 1.0 §5.1)"));
        }
        if (keys.stream().anyMatch(key -> key.get("alg") == null)) {
            findings.add(new Finding("Encryption keys in client_metadata.jwks must have an alg (OID4VP 1.0 §8.3)"));
        }
        validateEncryptionMethods(request.clientMetadata(), findings);
    }

    // OID4VP 1.0 §5.1: encrypted_response_enc_values_supported is mandatory for response modes
    // that require encryption
    private static void validateEncryptionMethods(Map<String, Object> clientMetadata, List<Finding> findings) {
        Object supported =
                clientMetadata == null ? null : clientMetadata.get("encrypted_response_enc_values_supported");
        if (!(supported instanceof List<?> values) || values.isEmpty()) {
            findings.add(
                    new Finding(
                            "client_metadata must contain a non-empty encrypted_response_enc_values_supported for response_mode direct_post.jwt (OID4VP 1.0 §5.1)"));
        }
    }

    private void validateClientIdPrefix(SignedJWT jwt, AuthorizationRequest request, List<Finding> findings) {
        String clientId = request.clientId();
        if (clientId == null) {
            return;
        }
        int separator = clientId.indexOf(':');
        String prefix = separator > 0 ? clientId.substring(0, separator) : "";
        String value = separator > 0 ? clientId.substring(separator + 1) : clientId;
        if ("x509_hash".equals(prefix)) {
            validateX509Hash(jwt, value, findings);
        } else {
            findings.add(new Finding("Client identifier prefix '" + prefix
                    + "' is not allowed; HAIP 1.0 mandates x509_hash for signed requests: " + clientId));
        }
    }

    private void validateX509Hash(SignedJWT jwt, String expectedHash, List<Finding> findings) {
        X509Certificate leaf = leafCertificate(jwt, findings);
        if (leaf == null) {
            return;
        }
        try {
            String actualHash = Base64URL.encode(
                            MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()))
                    .toString();
            if (!actualHash.equals(expectedHash)) {
                findings.add(
                        new Finding(
                                "x509_hash client_id does not match SHA-256 of the request object signing certificate (OID4VP 1.0 §5.9.1)"));
            }
        } catch (Exception e) {
            findings.add(new Finding("x509_hash comparison failed: " + e.getMessage()));
        }
        verifySignature(jwt, leaf, findings);
    }

    private static void verifySignature(SignedJWT jwt, X509Certificate leaf, List<Finding> findings) {
        try {
            if (!jwt.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey()))) {
                findings.add(
                        new Finding(
                                "Request object signature does not verify with the x5c leaf certificate key (OID4VP 1.0 §5.10)"));
            }
        } catch (Exception e) {
            findings.add(new Finding("Request object signature verification failed: " + e.getMessage()));
        }
    }

    private static X509Certificate leafCertificate(SignedJWT jwt, List<Finding> findings) {
        List<Base64> x5c = jwt.getHeader().getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            findings.add(
                    new Finding(
                            "x509 client identifier prefixes require the signing certificate in the x5c header (OID4VP 1.0 §5.9.1)"));
            return null;
        }
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(x5c.getFirst().decode()));
        } catch (Exception e) {
            findings.add(new Finding("x5c certificate cannot be parsed: " + e.getMessage()));
            return null;
        }
    }

    private static void validateDcqlStructure(AuthorizationRequest request, List<Finding> findings) {
        Map<String, Object> dcqlQuery = request.dcqlQuery();
        if (dcqlQuery == null) {
            findings.add(new Finding("dcql_query is required for a vp_token request (OID4VP 1.0 §5.1)"));
            return;
        }
        if (!(dcqlQuery.get("credentials") instanceof List<?> credentials) || credentials.isEmpty()) {
            findings.add(new Finding("dcql_query must contain a non-empty credentials array (OID4VP 1.0 §6.1)"));
            return;
        }
        List<String> queryIds = new ArrayList<>();
        for (Object entry : credentials) {
            if (!(entry instanceof Map<?, ?> credentialQuery)
                    || !(credentialQuery.get("id") instanceof String queryId)
                    || !(credentialQuery.get("format") instanceof String)) {
                findings.add(new Finding(
                        "Every dcql_query credential query needs string 'id' and 'format' members (OID4VP 1.0 §6.1)"));
                continue;
            }
            queryIds.add(queryId);
            validateTrustedAuthorities(credentialQuery, queryId, findings);
            validateClaimSets(credentialQuery, queryId, findings);
        }
        validateCredentialSets(dcqlQuery, queryIds, findings);
    }

    private static void validateTrustedAuthorities(Map<?, ?> credentialQuery, String queryId, List<Finding> findings) {
        if (!(credentialQuery.get("trusted_authorities") instanceof List<?> authorities)) {
            return;
        }
        for (Object entry : authorities) {
            if (!(entry instanceof Map<?, ?> authority)
                    || !(authority.get("type") instanceof String type)
                    || !(authority.get("values") instanceof List<?> values)
                    || values.isEmpty()) {
                findings.add(
                        new Finding(
                                "Credential query '" + queryId
                                        + "': every trusted_authorities entry needs a string 'type' and non-empty 'values' (OID4VP 1.0 §6.1.1)"));
                continue;
            }
            if (!("aki".equals(type) || "etsi_tl".equals(type))) {
                findings.add(new Finding("Credential query '" + queryId + "': unsupported trusted_authorities type '"
                        + type + "', this wallet supports aki and etsi_tl (OID4VP 1.0 §6.1.1)"));
            }
        }
    }

    private static void validateClaimSets(Map<?, ?> credentialQuery, String queryId, List<Finding> findings) {
        if (!(credentialQuery.get("claim_sets") instanceof List<?> claimSets)) {
            return;
        }
        List<String> claimIds = credentialQuery.get("claims") instanceof List<?> claims
                ? claims.stream()
                        .filter(claim -> claim instanceof Map<?, ?> map && map.get("id") instanceof String)
                        .map(claim -> (String) ((Map<?, ?>) claim).get("id"))
                        .toList()
                : List.of();
        for (Object option : claimSets) {
            if (!(option instanceof List<?> ids) || ids.isEmpty()) {
                findings.add(new Finding("Credential query '" + queryId
                        + "': claim_sets options must be non-empty arrays of claim ids (OID4VP 1.0 §6.4.2)"));
                continue;
            }
            ids.stream()
                    .filter(id -> !claimIds.contains(String.valueOf(id)))
                    .forEach(id -> findings.add(new Finding("Credential query '" + queryId
                            + "': claim_sets references unknown claim id '" + id + "' (OID4VP 1.0 §6.4.2)")));
        }
    }

    private static void validateCredentialSets(
            Map<String, Object> dcqlQuery, List<String> queryIds, List<Finding> findings) {
        if (!(dcqlQuery.get("credential_sets") instanceof List<?> credentialSets)) {
            return;
        }
        for (Object entry : credentialSets) {
            if (!(entry instanceof Map<?, ?> set)
                    || !(set.get("options") instanceof List<?> options)
                    || options.isEmpty()) {
                findings.add(
                        new Finding("Every credential_sets entry needs a non-empty options array (OID4VP 1.0 §6.3.1)"));
                continue;
            }
            for (Object option : options) {
                if (!(option instanceof List<?> ids) || ids.isEmpty()) {
                    findings.add(
                            new Finding(
                                    "credential_sets options must be non-empty arrays of credential query ids (OID4VP 1.0 §6.3.1)"));
                    continue;
                }
                ids.stream()
                        .filter(id -> !queryIds.contains(String.valueOf(id)))
                        .forEach(id ->
                                findings.add(new Finding("credential_sets references unknown credential query id '" + id
                                        + "' (OID4VP 1.0 §6.3.1)")));
            }
        }
    }

    private static SignedJWT parse(String rawRequestObject) {
        try {
            return SignedJWT.parse(rawRequestObject);
        } catch (ParseException e) {
            throw new IllegalStateException("Request object was parsed before validation", e);
        }
    }
}
