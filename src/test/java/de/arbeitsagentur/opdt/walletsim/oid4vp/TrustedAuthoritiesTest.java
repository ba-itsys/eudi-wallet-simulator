package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.Base64URL;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * trusted_authorities filtering (OID4VP 1.0 §6.1.1): credentials whose issuer does not match the
 * requested authority (aki or etsi_tl) must not be offered for presentation.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustedAuthoritiesTest {

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    @Test
    void akiMatchingTheIssuerCaOffersCredentials() throws Exception {
        try (TestVerifier verifier = new TestVerifier(dcqlWithTrustedAuthority("aki", caKeyIdentifier()))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).contains("data-credential-id=\"pid-maria-neumann\"");
        }
    }

    @Test
    void akiOfAForeignAuthorityOffersNoCredentials() throws Exception {
        try (TestVerifier verifier = new TestVerifier(dcqlWithTrustedAuthority(
                "aki", Base64URL.encode("foreign-authority").toString()))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).doesNotContain("data-credential-id");
            assertThat(picker).contains("No credential");
        }
    }

    @Test
    void etsiTlPointingAtTheOwnTrustListOffersCredentials() throws Exception {
        String trustListUrl = "http://localhost:" + port + "/api/trust-lists/credentials";
        try (TestVerifier verifier = new TestVerifier(dcqlWithTrustedAuthority("etsi_tl", trustListUrl))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).contains("data-credential-id=\"pid-maria-neumann\"");
        }
    }

    @Test
    void etsiTlPointingAtAnUnreachableListOffersNoCredentials() throws Exception {
        try (TestVerifier verifier =
                new TestVerifier(dcqlWithTrustedAuthority("etsi_tl", "http://localhost:1/trust-list"))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).doesNotContain("data-credential-id");
        }
    }

    private String caKeyIdentifier() throws Exception {
        X509CertificateHolder holder =
                new X509CertificateHolder(pki.caCertificate().getEncoded());
        SubjectKeyIdentifier ski = SubjectKeyIdentifier.fromExtensions(holder.getExtensions());
        assertThat(ski).as("CA certificate carries a SubjectKeyIdentifier").isNotNull();
        return Base64URL.encode(ski.getKeyIdentifier()).toString();
    }

    private static String dcqlWithTrustedAuthority(String type, String value) {
        return """
                {"credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["urn:eudi:pid:1"]},
                    "claims": [{"path": ["family_name"]}],
                    "trusted_authorities": [{"type": "%s", "values": ["%s"]}]
                }]}
                """
                .formatted(type, value);
    }
}
