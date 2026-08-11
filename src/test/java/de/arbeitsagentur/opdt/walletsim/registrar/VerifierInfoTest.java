package de.arbeitsagentur.opdt.walletsim.registrar;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

/**
 * EUDI: verifier_info must carry a registration certificate this wallet's registrar
 * accepts. The registrar issues rc-rp+jwt certificates via the API; requests without or with
 * foreign registration certificates get conformance findings.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerifierInfoTest {

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void issuesRegistrationCertificateSignedByRegistrar() throws Exception {
        JsonNode response = client().get()
                .uri("/api/registration-certificates?client_id=x509_san_dns:verifier.example.com&purpose=Login")
                .retrieve()
                .body(JsonNode.class);

        SignedJWT jwt = SignedJWT.parse(response.get("registrationCertificate").asText());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("rc-rp+jwt");
        assertThat(jwt.verify(new ECDSAVerifier(
                        (ECPublicKey) pki.registrarCertificate().getPublicKey())))
                .isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("x509_san_dns:verifier.example.com");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("purpose")).isEqualTo("Login");

        assertThat(response.get("verifierInfo").asText()).contains("\"format\":\"registrar_dataset\"");
    }

    @Test
    void missingVerifierInfoIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            ResponseEntity<String> picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("verifier_info");
        }
    }

    @Test
    void acceptedRegistrationCertificateProducesNoVerifierInfoFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            String verifierInfo = client().get()
                    .uri("/api/registration-certificates?client_id={id}", verifier.clientId())
                    .retrieve()
                    .body(JsonNode.class)
                    .get("verifierInfo")
                    .asText();
            verifier.withVerifierInfo(verifierInfo);
            ResponseEntity<String> picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody())
                    .as("the picker actually rendered")
                    .contains("data-credential-id=\"pid-maria-neumann\"");
            assertThat(picker.getBody()).doesNotContain("verifier_info");
        }
    }

    @Test
    void registrationCertificateForOtherClientIsAFinding() throws Exception {
        String verifierInfo = client().get()
                .uri("/api/registration-certificates?client_id=x509_san_dns:someone-else.example.com")
                .retrieve()
                .body(JsonNode.class)
                .get("verifierInfo")
                .asText();

        try (TestVerifier verifier = TestVerifier.pidVerifier().withVerifierInfo(verifierInfo)) {
            ResponseEntity<String> picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(picker.getBody()).contains("does not match the request client_id");
        }
    }

    private URI authorizeUri(TestVerifier verifier) {
        return URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
    }
}
