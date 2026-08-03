package de.arbeitsagentur.opdt.walletsim.attestation;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * OAuth attestation-based client authentication material: the wallet attestation is signed by the
 * wallet provider (anchored via the wallet-providers trust list), binds the holder key in cnf,
 * and the PoP is signed with exactly that holder key.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WalletAttestationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    @Test
    void walletAttestationAndPopFormAVerifiablePair() throws Exception {
        ResponseEntity<JsonNode> response = RestClient.create("http://localhost:" + port)
                .get()
                .uri("/api/wallet-attestation?client_id=test-client&aud=https://as.example.com")
                .retrieve()
                .toEntity(JsonNode.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        SignedJWT attestation =
                SignedJWT.parse(response.getBody().get("attestation").asText());
        assertThat(attestation.getHeader().getType().toString()).isEqualTo("oauth-client-attestation+jwt");

        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(
                        attestation.getHeader().getX509CertChain().getFirst().decode()));
        assertThat(leaf.getSubjectX500Principal())
                .isEqualTo(pki.walletProviderCertificate().getSubjectX500Principal());
        leaf.verify(pki.caCertificate().getPublicKey());
        assertThat(attestation.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())))
                .isTrue();

        Map<String, Object> claims = attestation.getJWTClaimsSet().getClaims();
        assertThat(attestation.getJWTClaimsSet().getSubject()).isEqualTo("test-client");
        assertThat(attestation.getJWTClaimsSet().getExpirationTime()).isInTheFuture();

        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) claims.get("cnf");
        ECKey holderKey = ECKey.parse(new ObjectMapper().writeValueAsString(cnf.get("jwk")));

        SignedJWT pop = SignedJWT.parse(response.getBody().get("pop").asText());
        assertThat(pop.getHeader().getType().toString()).isEqualTo("oauth-client-attestation-pop+jwt");
        assertThat(pop.verify(new ECDSAVerifier(holderKey.toECPublicKey())))
                .as("PoP signed with the attested holder key")
                .isTrue();
        assertThat(pop.getJWTClaimsSet().getIssuer()).isEqualTo("test-client");
        assertThat(pop.getJWTClaimsSet().getAudience()).containsExactly("https://as.example.com");
        assertThat(pop.getJWTClaimsSet().getJWTID()).isNotBlank();
    }
}
