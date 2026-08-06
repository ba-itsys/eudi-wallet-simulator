package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

/**
 * Wallet error handling per OID4VP 1.0 §8.5: rejected requests are answered with an error
 * response at the response_uri. In strict mode a non conformant request yields invalid_request.
 * For direct_post.jwt the error response is encrypted like any other response.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorHandlingTest {

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
    void strictRejectionSendsInvalidRequestToTheVerifier() throws Exception {
        client().put()
                .uri("/api/config/conformance")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("mode", "strict"))
                .retrieve()
                .toBodilessEntity();

        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("nonce"))) {
            ResponseEntity<String> page =
                    client().get().uri(authorizeUri(verifier)).retrieve().toEntity(String.class);
            assertThat(page.getBody()).contains("nonce");
            assertThat(page.getBody()).doesNotContain("data-credential-id");

            TestVerifier.ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("error")).isEqualTo("invalid_request");
            assertThat(response.formParameters().get("error_description")).contains("nonce");
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
        }
    }

    @Test
    void cancelOnEncryptedFlowSendsAccessDeniedAsJwe() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withEncryptedResponses()) {
            String picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().body(String.class);
            String flowState = extractHiddenField(picker, "flowState");

            ResponseEntity<String> cancel = client().post()
                    .uri("/authorize/cancel")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(cancel.getStatusCode().is3xxRedirection()).isTrue();

            TestVerifier.ReceivedResponse response = verifier.awaitResponse();
            String jwe = response.formParameters().get("response");
            assertThat(jwe)
                    .as("error response is encrypted for direct_post.jwt")
                    .isNotNull();

            EncryptedJWT encrypted = EncryptedJWT.parse(jwe);
            encrypted.decrypt(new ECDHDecrypter(verifier.responseEncryptionKey().toECPrivateKey()));
            assertThat(encrypted.getJWTClaimsSet().getClaim("error")).isEqualTo("access_denied");
            assertThat(encrypted.getJWTClaimsSet().getClaim("state")).isEqualTo(verifier.state());
        }
    }

    private static String extractHiddenField(String html, String name) {
        String marker = "name=\"" + name + "\" value=\"";
        int start = html.indexOf(marker);
        assertThat(start).as("hidden field '%s' present", name).isNotNegative();
        start += marker.length();
        return html.substring(start, html.indexOf('"', start));
    }

    private URI authorizeUri(TestVerifier verifier) {
        return URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
    }
}
