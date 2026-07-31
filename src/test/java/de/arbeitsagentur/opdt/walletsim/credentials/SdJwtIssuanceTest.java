package de.arbeitsagentur.opdt.walletsim.credentials;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Verifies issued SD-JWT VCs from the outside: signature against the x5c leaf, chain to the
 * simulator CA, disclosure digests, holder binding key and status list reference — the same checks
 * the keycloak-extension-oid4vp verifier performs.
 */
@SpringBootTest
class SdJwtIssuanceTest {

    @Autowired
    private CredentialStore credentialStore;

    @Autowired
    private SimulatorPki pki;

    @Test
    void issuedSdJwtVerifiesAgainstEmbeddedCertificateChain() throws Exception {
        StoredCredential credential = anyPredefinedCredential();

        String[] parts = credential.sdJwt().split("~");
        SignedJWT issuerJwt = SignedJWT.parse(parts[0]);

        List<com.nimbusds.jose.util.Base64> x5c = issuerJwt.getHeader().getX509CertChain();
        assertThat(x5c).isNotEmpty();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = x5c.stream()
                .map(encoded -> parseCertificate(certFactory, encoded.decode()))
                .toList();

        X509Certificate leaf = chain.getFirst();
        assertThat(issuerJwt.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())))
                .as("issuer JWT signature verifies with x5c leaf key")
                .isTrue();

        // leaf chains to the simulator CA; the self-signed trust anchor is not part of x5c
        leaf.verify(pki.caCertificate().getPublicKey());
        for (X509Certificate cert : chain) {
            assertThat(cert.getSubjectX500Principal())
                    .as("no self-signed trust anchor inside x5c")
                    .isNotEqualTo(cert.getIssuerX500Principal());
        }
    }

    @Test
    void issuedSdJwtCarriesVctHolderKeyStatusAndValidDisclosures() throws Exception {
        StoredCredential credential = anyPredefinedCredential();

        String[] parts = credential.sdJwt().split("~");
        SignedJWT issuerJwt = SignedJWT.parse(parts[0]);
        Map<String, Object> claims = issuerJwt.getJWTClaimsSet().getClaims();

        assertThat(issuerJwt.getHeader().getType().toString()).isEqualTo("dc+sd-jwt");
        assertThat(claims.get("vct")).isEqualTo("urn:eudi:pid:1");
        assertThat(claims).containsKey("iat");
        assertThat(claims).containsKey("exp");

        Map<String, Object> cnf = asMap(claims.get("cnf"));
        assertThat(asMap(cnf.get("jwk"))).containsEntry("kty", "EC");

        Map<String, Object> status = asMap(claims.get("status"));
        Map<String, Object> statusList = asMap(status.get("status_list"));
        assertThat(statusList.get("uri")).asString().endsWith("/status-list");
        assertThat(((Number) statusList.get("idx")).intValue()).isGreaterThanOrEqualTo(0);

        // every disclosure digest must be present in the issuer JWT _sd array
        assertThat(claims.get("_sd_alg")).isEqualTo("sha-256");
        @SuppressWarnings("unchecked")
        List<String> sdDigests = (List<String>) claims.get("_sd");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (int i = 1; i < parts.length; i++) {
            String expected = Base64URL.encode(digest.digest(parts[i].getBytes(StandardCharsets.US_ASCII)))
                    .toString();
            assertThat(sdDigests).contains(expected);
        }

        // disclosures cover the seed claims, e.g. family_name
        List<String> disclosedClaimNames = List.of(parts).subList(1, parts.length).stream()
                .map(d -> new String(Base64.getUrlDecoder().decode(d), StandardCharsets.UTF_8))
                .toList();
        assertThat(disclosedClaimNames).anyMatch(d -> d.contains("\"family_name\""));
    }

    private StoredCredential anyPredefinedCredential() {
        List<StoredCredential> credentials = credentialStore.findAll();
        assertThat(credentials).as("pre-defined credentials seeded from YAML").isNotEmpty();
        return credentials.getFirst();
    }

    private static X509Certificate parseCertificate(CertificateFactory factory, byte[] der) {
        try {
            return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }
}
