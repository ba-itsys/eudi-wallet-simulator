package de.arbeitsagentur.opdt.walletsim.conformance;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.ReceivedResponse;
import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;

/**
 * Strict mode is a static configuration option (app.mode). Non conformant requests are refused
 * without rendering the picker, and the wallet answers the verifier with an invalid_request
 * error response (OID4VP 1.0 §8.5).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "app.mode=strict")
class StrictModeTest {

    @LocalServerPort
    private int port;

    @Test
    void configReportsStrictMode() {
        JsonNode config = client(port).get().uri("/api/config").retrieve().body(JsonNode.class);
        assertThat(config.get("mode").asText()).isEqualTo("strict");
    }

    @Test
    void strictModeRefusesAndSendsInvalidRequestToTheVerifier() throws Exception {
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("nonce"))) {
            ResponseEntity<String> page = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(page.getBody()).contains("nonce");
            assertThat(page.getBody())
                    .as("strict mode does not render the picker")
                    .doesNotContain("data-credential-id");

            ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("error")).isEqualTo("invalid_request");
            assertThat(response.formParameters().get("error_description")).contains("nonce");
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
        }
    }
}
