package de.arbeitsagentur.opdt.walletsim.credentials;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppProperties;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Issues SD-JWT VCs signed with the simulator issuer key. Claims are made selectively
 * disclosable recursively, including nested objects and array elements. Claim paths listed as
 * always disclosed stay plain members of the JWT body, so every verifier sees them. The header
 * carries the leaf certificate only, the CA trust anchor is published via the trust list.
 * Definitions marked untrustedIssuer are signed by the ad hoc untrusted issuer instead, which no
 * trust list anchors.
 */
@Component
public class SdJwtIssuer {

    private static final String SD_JWT_VC_TYP = "dc+sd-jwt";

    private final SimulatorPki pki;
    private final AppProperties properties;

    public SdJwtIssuer(SimulatorPki pki, AppProperties properties) {
        this.pki = pki;
        this.properties = properties;
    }

    // statusIndex is null for credentials that exist only for a single presentation, they get no
    // status list reference because nothing can revoke them
    public String issue(CredentialDefinition definition, Integer statusIndex, ECKey holderKey) {
        try {
            List<Disclosure> disclosures = new ArrayList<>();
            Map<String, Object> encodedClaims =
                    encodeObject(definition.claims(), "", definition.alwaysDisclosedClaims(), disclosures);

            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(properties.externalUrl())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(definition.validityDays(), ChronoUnit.DAYS)))
                    .claim("vct", definition.vct())
                    .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
            if (statusIndex != null) {
                claims.claim(
                        "status", Map.of("status_list", Map.of("uri", properties.statusListUri(), "idx", statusIndex)));
            }
            encodedClaims.forEach(claims::claim);

            X509Certificate signingCertificate =
                    definition.untrustedIssuer() ? pki.untrustedIssuerCertificate() : pki.issuerCertificate();
            PrivateKey signingKey =
                    definition.untrustedIssuer() ? pki.untrustedIssuerPrivateKey() : pki.issuerPrivateKey();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(SD_JWT_VC_TYP))
                    .x509CertChain(List.of(Base64.encode(signingCertificate.getEncoded())))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new ECDSASigner((ECPrivateKey) signingKey));

            return new SDJWT(jwt.serialize(), disclosures).toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue SD-JWT VC for " + definition.id(), e);
        }
    }

    private static Map<String, Object> encodeObject(
            Map<String, Object> claims, String prefix, List<String> alwaysDisclosed, List<Disclosure> disclosures) {
        SDObjectBuilder builder = new SDObjectBuilder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = encodeValue(entry.getValue(), path, alwaysDisclosed, disclosures);
            if (alwaysDisclosed.contains(path)) {
                builder.putClaim(entry.getKey(), value);
            } else {
                disclosures.add(builder.putSDClaim(entry.getKey(), value));
            }
        }
        // the flag writes _sd_alg, which RFC 9901 §4.1.1 allows at the top level of the payload
        // only, so nested objects never carry it
        boolean topLevel = prefix.isEmpty();
        return builder.build(topLevel && !disclosures.isEmpty());
    }

    @SuppressWarnings("unchecked")
    private static Object encodeValue(
            Object value, String path, List<String> alwaysDisclosed, List<Disclosure> disclosures) {
        if (value instanceof Map<?, ?> nested) {
            return encodeObject((Map<String, Object>) nested, path, alwaysDisclosed, disclosures);
        }
        if (value instanceof List<?> list) {
            // elements become individually disclosable only when the array claim itself is always
            // disclosed, otherwise the whole array is already hidden behind one disclosure
            boolean disclosePerElement = alwaysDisclosed.contains(path);
            List<Object> encoded = new ArrayList<>();
            for (int i = 0; i < list.size(); i++) {
                String elementPath = path + "." + i;
                Object element = encodeValue(list.get(i), elementPath, alwaysDisclosed, disclosures);
                if (!disclosePerElement || alwaysDisclosed.contains(elementPath)) {
                    encoded.add(element);
                } else {
                    Disclosure disclosure = new Disclosure(element);
                    disclosures.add(disclosure);
                    encoded.add(disclosure.toArrayElement());
                }
            }
            return encoded;
        }
        return value;
    }
}
