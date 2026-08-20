package de.arbeitsagentur.opdt.walletsim.registrar;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;

/**
 * EUDI: verifier_info must carry a registration certificate this wallet's registrar
 * accepts. The registrar issues rc-wrp+jwt certificates (ETSI TS 119 475) via the API; requests
 * without or with foreign registration certificates get conformance findings.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerifierInfoTest {

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    @Test
    void issuesRegistrationCertificateSignedByRegistrar() throws Exception {
        JsonNode response = client(port)
                .get()
                .uri("/api/registration-certificates?client_id=x509_san_dns:verifier.example.com&purpose=Login")
                .retrieve()
                .body(JsonNode.class);

        SignedJWT jwt = SignedJWT.parse(response.get("registrationCertificate").asText());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("rc-wrp+jwt");
        assertThat(jwt.verify(new ECDSAVerifier(
                        (ECPublicKey) pki.registrarCertificate().getPublicKey())))
                .isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("x509_san_dns:verifier.example.com");
        assertThat(jwt.getJWTClaimsSet().getListClaim("purpose"))
                .containsExactly(Map.of("lang", "en", "value", "Login"));

        assertThat(response.get("verifierInfo").asText())
                .as("the data member carries the compact rc-wrp+jwt, which is what verifiers send")
                .contains("\"format\":\"registration_cert\"")
                .contains(
                        "\"data\":\"" + response.get("registrationCertificate").asText() + "\"");
    }

    @Test
    void missingVerifierInfoIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("verifier_info");
        }
    }

    @Test
    void acceptedRegistrationCertificateProducesNoVerifierInfoFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            String verifierInfo = client(port)
                    .get()
                    .uri("/api/registration-certificates?client_id={id}", verifier.clientId())
                    .retrieve()
                    .body(JsonNode.class)
                    .get("verifierInfo")
                    .asText();
            verifier.withVerifierInfo(verifierInfo);
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody())
                    .as("the picker actually rendered")
                    .contains("data-credential-id=\"pid-jan-hart\"");
            assertThat(picker.getBody()).doesNotContain("verifier_info");
        }
    }

    /**
     * ETSI TS 119 475: sub is the registered legal-entity identifier, not the OpenID4VP
     * client_id, so a certificate whose sub differs from the request client_id is still accepted.
     */
    @Test
    void registrationCertificateWithForeignSubIsAccepted() throws Exception {
        String verifierInfo = client(port)
                .get()
                .uri("/api/registration-certificates?client_id=LEIEU-987654321")
                .retrieve()
                .body(JsonNode.class)
                .get("verifierInfo")
                .asText();

        try (TestVerifier verifier = TestVerifier.pidVerifier().withVerifierInfo(verifierInfo)) {
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).doesNotContain("verifier_info");
        }
    }
}
