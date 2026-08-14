package de.arbeitsagentur.opdt.walletsim.conformance;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;

/**
 * Debug mode (the default) surfaces verifier conformance findings as warnings and continues.
 * Findings are also written to the log.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConformanceModeTest {

    @LocalServerPort
    private int port;

    @Test
    void debugModeWarnsAboutMissingNonceAndContinues() throws Exception {
        try (var verifier = TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("nonce"))) {
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("nonce");
            assertThat(picker.getBody())
                    .as("flow continues in debug mode")
                    .contains("data-credential-id=\"pid-maria-neumann\"");
        }
    }

    @Test
    void conformantRequestShowsNoWarnings() throws Exception {
        try (var verifier = TestVerifier.pidVerifier().withEncryptedResponses()) {
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
                    .contains("data-credential-id=\"pid-maria-neumann\"");
            assertThat(picker.getBody()).doesNotContain("conformance-warnings");
        }
    }
}
