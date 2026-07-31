package de.arbeitsagentur.opdt.walletsim.credentials;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Issues SD-JWT VCs signed with the simulator issuer key. All claims are selectively disclosable
 * as top-level disclosures; the header carries the leaf certificate only (the CA trust anchor is
 * published via the trust list, not inside x5c).
 */
@Component
public class SdJwtIssuer {

    private static final String SD_JWT_VC_TYP = "dc+sd-jwt";

    private final SimulatorPki pki;
    private final AppUrls urls;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom random = new SecureRandom();

    public SdJwtIssuer(SimulatorPki pki, AppUrls urls) {
        this.pki = pki;
        this.urls = urls;
    }

    public String issue(CredentialDefinition definition, int statusIndex) {
        try {
            List<String> disclosures = new ArrayList<>();
            List<String> digests = new ArrayList<>();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, Object> claim : definition.claims().entrySet()) {
                String disclosure = encodeDisclosure(claim.getKey(), claim.getValue());
                disclosures.add(disclosure);
                digests.add(Base64URL.encode(sha256.digest(disclosure.getBytes(StandardCharsets.US_ASCII)))
                        .toString());
            }
            Collections.shuffle(digests, random);

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(urls.baseUrl())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(definition.validityDays(), ChronoUnit.DAYS)))
                    .claim("vct", definition.vct())
                    .claim("cnf", Map.of("jwk", pki.holderKey().toPublicJWK().toJSONObject()))
                    .claim("status", Map.of("status_list", Map.of("uri", urls.statusListUri(), "idx", statusIndex)))
                    .claim("_sd", digests)
                    .claim("_sd_alg", "sha-256")
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(SD_JWT_VC_TYP))
                    .x509CertChain(List.of(Base64.encode(pki.issuerCertificate().getEncoded())))
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner((ECPrivateKey) pki.issuerPrivateKey()));

            StringBuilder sdJwt = new StringBuilder(jwt.serialize());
            for (String disclosure : disclosures) {
                sdJwt.append('~').append(disclosure);
            }
            sdJwt.append('~');
            return sdJwt.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue SD-JWT VC for " + definition.id(), e);
        }
    }

    private String encodeDisclosure(String claimName, Object value) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        List<Object> disclosure = List.of(Base64URL.encode(salt).toString(), claimName, value);
        return Base64URL.encode(objectMapper.writeValueAsBytes(disclosure)).toString();
    }
}
