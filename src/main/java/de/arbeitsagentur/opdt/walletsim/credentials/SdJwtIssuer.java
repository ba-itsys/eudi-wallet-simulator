package de.arbeitsagentur.opdt.walletsim.credentials;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectEncoder;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Issues SD-JWT VCs signed with the simulator issuer key. All claims are selectively disclosable
 * recursively, including nested objects and array elements. The header carries the leaf
 * certificate only, the CA trust anchor is published via the trust list.
 */
@Component
public class SdJwtIssuer {

    private static final String SD_JWT_VC_TYP = "dc+sd-jwt";

    private final SimulatorPki pki;
    private final AppUrls urls;

    public SdJwtIssuer(SimulatorPki pki, AppUrls urls) {
        this.pki = pki;
        this.urls = urls;
    }

    public String issue(CredentialDefinition definition, int statusIndex, ECKey holderKey) {
        try {
            SDObjectEncoder encoder = new SDObjectEncoder().noDecoy();
            Map<String, Object> encodedClaims = encoder.encode(definition.claims());
            List<Disclosure> disclosures = encoder.getDisclosures();

            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(urls.baseUrl())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(definition.validityDays(), ChronoUnit.DAYS)))
                    .claim("vct", definition.vct())
                    .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                    .claim("status", Map.of("status_list", Map.of("uri", urls.statusListUri(), "idx", statusIndex)));
            encodedClaims.forEach(claims::claim);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(SD_JWT_VC_TYP))
                    .x509CertChain(List.of(Base64.encode(pki.issuerCertificate().getEncoded())))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new ECDSASigner((ECPrivateKey) pki.issuerPrivateKey()));

            StringBuilder sdJwt = new StringBuilder(jwt.serialize());
            for (Disclosure disclosure : disclosures) {
                sdJwt.append('~').append(disclosure.getDisclosure());
            }
            sdJwt.append('~');
            return sdJwt.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue SD-JWT VC for " + definition.id(), e);
        }
    }
}
