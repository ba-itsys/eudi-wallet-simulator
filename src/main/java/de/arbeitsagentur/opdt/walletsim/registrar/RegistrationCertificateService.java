package de.arbeitsagentur.opdt.walletsim.registrar;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppProperties;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Registrar for relying-party registration certificates (EUDI): issues rc-wrp+jwt tokens
 * (ETSI TS 119 475) signed with the persisted registrar key and validates presented ones against
 * exactly that key, so certificates generated here remain accepted across restarts.
 */
@Service
public class RegistrationCertificateService {

    public static final String REGISTRATION_CERTIFICATE_TYP = "rc-wrp+jwt";

    private static final long VALIDITY_DAYS = 365;

    private final SimulatorPki pki;
    private final AppProperties properties;

    public RegistrationCertificateService(SimulatorPki pki, AppProperties properties) {
        this.pki = pki;
        this.properties = properties;
    }

    // Issues a registration certificate for the given relying party client_id.
    public String issue(String clientId, String purpose) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(properties.baseUrl() + "/registrar")
                    .subject(clientId)
                    .issueTime(Date.from(now))
                    .notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(VALIDITY_DAYS, ChronoUnit.DAYS)))
                    .claim("status", "active");
            if (StringUtils.hasText(purpose)) {
                // ETSI TS 119 475 localizes purpose as an array of {lang, value} entries
                claims.claim("purpose", List.of(Map.of("lang", "en", "value", purpose)));
            }
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType(REGISTRATION_CERTIFICATE_TYP))
                            .x509CertChain(List.of(
                                    Base64.encode(pki.registrarCertificate().getEncoded())))
                            .build(),
                    claims.build());
            jwt.sign(new ECDSASigner((ECPrivateKey) pki.registrarPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue registration certificate for " + clientId, e);
        }
    }

    /**
     * Validates a presented registration certificate; returns the violation, or empty when the
     * certificate is one this registrar accepts. The sub claim is the registered legal-entity
     * identifier (ETSI TS 119 475), not the OpenID4VP client_id, so it is deliberately not
     * compared against the request.
     */
    public Optional<String> validate(String registrationCertificateJwt) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(registrationCertificateJwt);
        } catch (ParseException e) {
            return Optional.of("registration certificate is not a valid JWT");
        }
        try {
            if (jwt.getHeader().getType() == null
                    || !REGISTRATION_CERTIFICATE_TYP.equals(
                            jwt.getHeader().getType().toString())) {
                return Optional.of("registration certificate typ must be '" + REGISTRATION_CERTIFICATE_TYP + "', got: "
                        + jwt.getHeader().getType());
            }
            if (!jwt.verify(
                    new ECDSAVerifier((ECPublicKey) pki.registrarCertificate().getPublicKey()))) {
                return Optional.of("registration certificate is not signed by this wallet's registrar");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims.getExpirationTime() == null
                    || claims.getExpirationTime().toInstant().isBefore(Instant.now())) {
                return Optional.of("registration certificate is expired");
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.of("registration certificate validation failed: " + e.getMessage());
        }
    }
}
