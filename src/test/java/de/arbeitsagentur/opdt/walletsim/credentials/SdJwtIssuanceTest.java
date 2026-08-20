package de.arbeitsagentur.opdt.walletsim.credentials;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.disclosures;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Verifies issued SD-JWT VCs from the outside: signature against the x5c leaf, chain to the
 * simulator CA, disclosure digests, holder binding key and status list reference, mirroring what verifiers check.
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

        SignedJWT issuerJwt = issuerJwt(credential.sdJwt());

        List<Base64> x5c = issuerJwt.getHeader().getX509CertChain();
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

        SignedJWT issuerJwt = issuerJwt(credential.sdJwt());
        Map<String, Object> claims = issuerJwt.getJWTClaimsSet().getClaims();

        assertThat(issuerJwt.getHeader().getType().toString()).isEqualTo("dc+sd-jwt");
        assertThat(claims.get("vct")).isEqualTo("urn:eudi:pid:1");
        assertThat(claims).containsKey("iat");
        assertThat(claims).containsKey("exp");

        Map<String, Object> cnf = asMap(claims.get("cnf"));
        assertThat(asMap(cnf.get("jwk"))).containsEntry("kty", "EC");

        Map<String, Object> status = asMap(claims.get("status"));
        Map<String, Object> statusList = asMap(status.get("status_list"));
        assertThat(statusList.get("uri")).asString().endsWith("/api/status-list");
        assertThat(((Number) statusList.get("idx")).intValue()).isGreaterThanOrEqualTo(0);

        // all disclosures decode back to the original claims, including nested structures
        Map<String, Object> decoded = new SDObjectDecoder().decode(claims, disclosures(credential.sdJwt()));
        assertThat(decoded.get("family_name")).isEqualTo("'t Hart");
        assertThat(asMap(decoded.get("address")).get("locality")).isEqualTo("Leiden");
        assertThat((List<?>) decoded.get("nationalities")).isEqualTo(List.of("NL"));
    }

    @Test
    void hashAlgorithmClaimAppearsOnlyAtTheTopLevel() throws Exception {
        StoredCredential credential = anyPredefinedCredential();

        Map<String, Object> claims =
                issuerJwt(credential.sdJwt()).getJWTClaimsSet().getClaims();
        assertThat(claims).containsEntry("_sd_alg", "sha-256");

        // RFC 9901 §4.1.1: _sd_alg must not be used in any object nested within the payload
        for (Disclosure disclosure : disclosures(credential.sdJwt())) {
            assertThat(nestedHashAlgorithmClaims(disclosure.getClaimValue()))
                    .as("disclosure of %s carries no nested _sd_alg", disclosure.getClaimName())
                    .isEmpty();
        }
    }

    private static List<String> nestedHashAlgorithmClaims(Object node) {
        List<String> found = new ArrayList<>();
        if (node instanceof Map<?, ?> map) {
            map.forEach((key, value) -> {
                if ("_sd_alg".equals(key)) {
                    found.add(String.valueOf(value));
                }
                found.addAll(nestedHashAlgorithmClaims(value));
            });
        } else if (node instanceof List<?> list) {
            list.forEach(element -> found.addAll(nestedHashAlgorithmClaims(element)));
        }
        return found;
    }

    private StoredCredential anyPredefinedCredential() {
        List<StoredCredential> credentials = credentialStore.findAll();
        assertThat(credentials).as("pre-defined credentials seeded from YAML").isNotEmpty();
        return credentials.getFirst();
    }

    private static X509Certificate parseCertificate(CertificateFactory factory, byte[] der) {
        try {
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
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
