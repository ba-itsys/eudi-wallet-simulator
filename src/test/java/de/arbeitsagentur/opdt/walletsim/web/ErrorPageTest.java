package de.arbeitsagentur.opdt.walletsim.web;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * What the user sees when a presentation does not complete. A verifier can refuse a presentation
 * for reasons the wallet cannot know, so its answer is shown instead of a bare "request failed".
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorPageTest {

    @LocalServerPort
    private int port;

    @Test
    void verifierRejectionShowsWhatTheVerifierSaid() throws Exception {
        String rejection = "{\"error\":\"identity_provider_error\","
                + "\"error_description\":\"the wallet presented type 'urn:eudi:pid:de:1'\"}";
        try (TestVerifier verifier = TestVerifier.pidVerifier().withRejectedResponses(400, rejection)) {
            ResponseEntity<String> page = present(verifier, "pid-thomas-bauer");

            assertThat(page.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(page.getBody()).contains("The presentation did not complete");
            assertThat(page.getBody())
                    .as("the status code says who refused")
                    .contains("The verifier rejected the presentation with HTTP 400");
            assertThat(page.getBody())
                    .as("the verifier's own reason is the useful part")
                    .contains("identity_provider_error: the wallet presented type &#39;urn:eudi:pid:de:1&#39;");
            assertThat(page.getBody()).contains("id=\"back-to-wallet\"");
        }
    }

    @Test
    void verifierRejectionWithoutOauthErrorShowsTheRawAnswer() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withRejectedResponses(500, "backend exploded")) {
            ResponseEntity<String> page = present(verifier, "pid-jan-hart");

            assertThat(page.getBody()).contains("The verifier rejected the presentation with HTTP 500");
            assertThat(page.getBody()).contains("backend exploded");
        }
    }

    @Test
    void unreachableVerifierSaysSoInsteadOfBlamingTheResponse() throws Exception {
        String flowState;
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");
        }
        // the verifier is closed now, so its response_uri no longer accepts anything
        ResponseEntity<String> page = submit(flowState, "pid-jan-hart");

        assertThat(page.getBody()).contains("Could not reach the verifier at");
    }

    /**
     * Error pages are rendered from an exception handler, where Spring does not invoke
     * {@code @ModelAttribute} methods. The basepath has to reach them anyway or every asset link
     * on the page breaks.
     */
    @Test
    void errorPagesLinkTheirAssets() {
        ResponseEntity<String> page = client(port)
                .post()
                .uri("/credentials/edit")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("credentialId=does-not-exist")
                .retrieve()
                .toEntity(String.class);

        assertThat(page.getBody()).contains("Unknown credential");
        assertThat(page.getBody()).contains("href=\"/webjars/bootstrap/");
        assertThat(page.getBody()).contains("href=\"/css/layout.css\"");
        assertThat(page.getBody()).doesNotContain("null/");
    }

    private ResponseEntity<String> present(TestVerifier verifier, String credentialId) throws Exception {
        String picker =
                client(port).get().uri(authorizeUri(port, verifier)).retrieve().body(String.class);
        return submit(hiddenField(picker, "flowState"), credentialId);
    }

    private ResponseEntity<String> submit(String flowState, String credentialId) {
        return client(port)
                .post()
                .uri("/authorize/submit")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("selection%5Bpid%5D=" + credentialId + "&flowState="
                        + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                .retrieve()
                .toEntity(String.class);
    }
}
