package de.arbeitsagentur.opdt.walletsim.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
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

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void configReportsStrictMode() {
        JsonNode config = client().get().uri("/api/config").retrieve().body(JsonNode.class);
        assertThat(config.get("mode").asText()).isEqualTo("strict");
    }

    @Test
    void strictModeRefusesAndSendsInvalidRequestToTheVerifier() throws Exception {
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("nonce"))) {
            ResponseEntity<String> page =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(page.getBody()).contains("nonce");
            assertThat(page.getBody())
                    .as("strict mode does not render the picker")
                    .doesNotContain("data-credential-id");

            TestVerifier.ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("error")).isEqualTo("invalid_request");
            assertThat(response.formParameters().get("error_description")).contains("nonce");
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
        }
    }

    private URI authorizeUri(TestVerifier verifier) {
        return URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
    }
}
