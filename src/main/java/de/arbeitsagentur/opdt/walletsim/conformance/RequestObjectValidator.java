package de.arbeitsagentur.opdt.walletsim.conformance;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.oid4vp.AuthorizationRequest;
import de.arbeitsagentur.opdt.walletsim.oid4vp.ClientMetadataKeys;
import de.arbeitsagentur.opdt.walletsim.registrar.RegistrationCertificateService;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Collects verifier conformance findings against OpenID4VP 1.0 plus the BA profile requirement
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

    public List<Finding> validate(String queryClientId, AuthorizationRequest request) {
        List<Finding> findings = new ArrayList<>();
        SignedJWT jwt = parse(request.rawRequestObject());

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
        validateVerifierInfo(jwt, request, findings);
        return findings;
    }

    private void validateVerifierInfo(SignedJWT jwt, AuthorizationRequest request, List<Finding> findings) {
        Object verifierInfo;
        try {
            verifierInfo = jwt.getJWTClaimsSet().getClaim("verifier_info");
        } catch (java.text.ParseException e) {
            findings.add(new Finding("verifier_info cannot be read: " + e.getMessage()));
            return;
        }
        if (verifierInfo == null) {
            findings.add(new Finding(
                    "verifier_info with a registration certificate is required (BA profile, OID4VP 1.0 §5.11)"));
            return;
        }
        if (!(verifierInfo instanceof List<?> attestations) || attestations.isEmpty()) {
            findings.add(new Finding("verifier_info must be a non-empty array of attestations (OID4VP 1.0 §5.11)"));
            return;
        }
        for (Object entry : attestations) {
            if (!(entry instanceof Map<?, ?> attestation)
                    || !("jwt".equals(attestation.get("format")))
                    || !(attestation.get("data") instanceof String data)) {
                findings.add(new Finding(
                        "Every verifier_info attestation needs format 'jwt' and string 'data' (OID4VP 1.0 §5.11)"));
                continue;
            }
            registrationCertificates
                    .validate(data, request.clientId())
                    .ifPresent(violation -> findings.add(new Finding("verifier_info: " + violation)));
        }
    }

    private static void validateResponseMode(AuthorizationRequest request, List<Finding> findings) {
        String responseMode = request.responseMode();
        if (responseMode == null || !(responseMode.equals("direct_post") || responseMode.equals("direct_post.jwt"))) {
            findings.add(new Finding(
                    "response_mode must be direct_post or direct_post.jwt for a web wallet (OID4VP 1.0 §8.2), got: "
                            + responseMode));
            return;
        }
        if (request.responseUri() == null
                || !(request.responseUri().startsWith("http://")
                        || request.responseUri().startsWith("https://"))) {
            findings.add(new Finding(
                    "response_uri must be an absolute http(s) URL (OID4VP 1.0 §8.2), got: " + request.responseUri()));
        }
        if ("direct_post.jwt".equals(responseMode)) {
            if (ClientMetadataKeys.encryptionKeys(request.clientMetadata()).isEmpty()) {
                findings.add(
                        new Finding(
                                "response_mode direct_post.jwt requires a usable EC encryption key in client_metadata.jwks (OID4VP 1.0 §8.3)"));
            }
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
        List<com.nimbusds.jose.util.Base64> x5c = jwt.getHeader().getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            findings.add(
                    new Finding(
                            "x509 client identifier prefixes require the signing certificate in the x5c header (OID4VP 1.0 §5.9.1)"));
            return null;
        }
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(
                            new java.io.ByteArrayInputStream(x5c.getFirst().decode()));
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
        for (Object entry : credentials) {
            if (!(entry instanceof Map<?, ?> credentialQuery)
                    || !(credentialQuery.get("id") instanceof String)
                    || !(credentialQuery.get("format") instanceof String)) {
                findings.add(new Finding(
                        "Every dcql_query credential query needs string 'id' and 'format' members (OID4VP 1.0 §6.1)"));
            }
        }
    }

    private static SignedJWT parse(String rawRequestObject) {
        try {
            return SignedJWT.parse(rawRequestObject);
        } catch (java.text.ParseException e) {
            throw new IllegalStateException("Request object was parsed before validation", e);
        }
    }
}
