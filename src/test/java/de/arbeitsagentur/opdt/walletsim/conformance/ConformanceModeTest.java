package de.arbeitsagentur.opdt.walletsim.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

/**
 * Debug mode surfaces verifier conformance findings as warnings and continues; strict mode
 * refuses the request without posting anything. The mode is switchable at runtime via the config
 * API, and findings land in the activity log.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConformanceModeTest {

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @AfterEach
    void resetConformanceMode() {
        client().delete().uri("/api/config/conformance").retrieve().toBodilessEntity();
    }

    @Test
    void debugModeWarnsAboutMissingNonceAndContinues() throws Exception {
        try (var verifier = TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("nonce"))) {
            ResponseEntity<String> picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("nonce");
            assertThat(picker.getBody())
                    .as("flow continues in debug mode")
                    .contains("data-credential-id=\"pid-maria-neumann\"");

            JsonNode log = client().get().uri("/api/log").retrieve().body(JsonNode.class);
            assertThat(log.toString()).contains("nonce");
        }
    }

    @Test
    void strictModeRefusesNonConformantRequest() throws Exception {
        ResponseEntity<JsonNode> configured = client().put()
                .uri("/api/config/conformance")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("mode", "strict"))
                .retrieve()
                .toEntity(JsonNode.class);
        assertThat(configured.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(client().get()
                        .uri("/api/config")
                        .retrieve()
                        .body(JsonNode.class)
                        .get("conformanceMode")
                        .asText())
                .isEqualTo("strict");

        try (var verifier = TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("nonce"))) {
            ResponseEntity<String> response =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(response.getBody()).contains("nonce");
            assertThat(response.getBody())
                    .as("strict mode does not render the picker")
                    .doesNotContain("data-credential-id");
        }
    }

    @Test
    void conformantRequestShowsNoWarnings() throws Exception {
        try (var verifier = TestVerifier.pidVerifier()) {
            ResponseEntity<String> picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).doesNotContain("conformance-warnings");
        }
    }

    private URI authorizeUri(TestVerifier verifier) {
        return URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
    }
}
