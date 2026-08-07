package de.arbeitsagentur.opdt.walletsim.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

/**
 * Debug mode (the default) surfaces verifier conformance findings as warnings and continues.
 * Findings land in the activity log.
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
        }
    }

    @Test
    void conformantRequestShowsNoWarnings() throws Exception {
        try (var verifier = TestVerifier.pidVerifier()) {
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
